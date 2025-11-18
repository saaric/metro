#![windows_subsystem = "windows"]

use anyhow::{Context, Result};
use clap::Parser;
use ctrlc;
use env_logger;
use log::{error, info, warn};
use ssh2::Session;
use std::collections::HashSet;
use std::fs::File;
use std::io::{self, BufRead, Read, Write};
use std::net::{TcpListener, TcpStream, ToSocketAddrs};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

#[derive(Parser, Debug, Clone)]
#[command(name = "metro", about = "Simple SSH tunneling tool (Rust edition)")]
pub(crate) struct Args {
    /// Host for SSH
    #[arg(long)]
    host: String,

    /// Port for SSH
    #[arg(long, default_value = "22")]
    port: u16,

    /// User for SSH
    #[arg(long)]
    user: String,

    /// Password for SSH
    #[arg(long)]
    password: String,

    /// Timeout for SSH connection in seconds
    #[arg(long, default_value = "20")]
    timeout: u64,

    /// Max retries to establish SSH after a failure (0 = retry forever)
    #[arg(long, default_value = "0")]
    retries: u32,

    /// Seconds to wait between SSH reconnect attempts
    #[arg(long, default_value = "5")]
    retry_interval: u64,

    /// Enable SSH keepalive pings (seconds, 0 = disabled)
    #[arg(long, default_value = "30")]
    keepalive: u32,

    /// Seconds to wait for local bind if port is busy (0 = fail immediately)
    #[arg(long, default_value = "0")]
    bind_wait: u64,

    /// CSV list of tunnels. Supported formats per line:
    /// - "<local_port>;<remote_host>:<remote_port>" for static local forwarding
    /// - "D<local_port>" or "<local_port>;D" for dynamic SOCKS5 forwarding on <local_port>
    #[arg(long, value_name = "FILE")]
    list: PathBuf,

    /// Launch a simple GUI editor for the tunnels list and exit
    #[arg(long, default_value_t = false)]
    gui: bool,
}

#[derive(Debug, Clone)]
enum TunnelKind {
    Static {
        remote_host: String,
        remote_port: u16,
    },
    Dynamic,
}

#[derive(Debug, Clone)]
struct TunnelCfg {
    local_port: u16,
    kind: TunnelKind,
}

mod gui;

fn main() -> Result<()> {
    env_logger::init();
    let args = Args::parse();

    // If GUI is requested, open the editor for the tunnels file and exit.
    if args.gui {
        return gui::run_gui(&args);
    }

    let tunnels = read_tunnels(&args.list)
        .with_context(|| format!("Failed to read tunnels file: {:?}", args.list))?;

    if tunnels.is_empty() {
        anyhow::bail!("No tunnels found in file");
    }

    info!("Connecting to ssh endpoint {}:{} ...", args.host, args.port);

    let shutdown = Arc::new(AtomicBool::new(false));
    {
        let shutdown = shutdown.clone();
        ctrlc::set_handler(move || {
            shutdown.store(true, Ordering::SeqCst);
        })
        .context("failed to install Ctrl+C handler")?;
    }

    info!("Press Ctrl+C to close.");

    // Spawn a listener thread per tunnel
    let mut handles = Vec::new();
    for t in tunnels {
        let a = args.clone();
        let s = shutdown.clone();
        let handle = thread::spawn(move || {
            if let Err(e) = run_tunnel(&a, &t, s) {
                match &t.kind {
                    TunnelKind::Static {
                        remote_host,
                        remote_port,
                    } => {
                        error!(
                            "Tunnel {} -> {}:{} failed: {:#}",
                            t.local_port, remote_host, remote_port, e
                        );
                    }
                    TunnelKind::Dynamic => {
                        error!("Dynamic SOCKS tunnel {} failed: {:#}", t.local_port, e);
                    }
                }
            }
        });
        handles.push(handle);
    }

    for h in handles {
        let _ = h.join();
    }

    info!("Bye bye");
    Ok(())
}

fn read_tunnels(path: &PathBuf) -> Result<Vec<TunnelCfg>> {
    info!("Reading tunnel file: {:?}", path);
    let file = File::open(path)?;
    let reader = io::BufReader::new(file);
    let mut res = Vec::new();
    let mut used_ports: HashSet<u16> = HashSet::new();
    for line in reader.lines() {
        let line_string = line?;
        let mut line = line_string.trim();
        // Strip full-line or inline comments starting with '#'
        if let Some(hash) = line.find('#') {
            line = line[..hash].trim();
        }
        if line.is_empty() {
            continue;
        }

        // Support formats:
        // 1) "<local_port>;<remote_host>:<remote_port>" (static)
        // 2) "D<port>" (dynamic SOCKS on <port>)
        // 3) "<local_port>;D" (dynamic SOCKS on <local_port>)
        if line.starts_with('D') || line.starts_with('d') {
            let port_str = &line[1..];
            match port_str.parse::<u16>() {
                Ok(local_port) => {
                    if used_ports.insert(local_port) {
                        res.push(TunnelCfg {
                            local_port,
                            kind: TunnelKind::Dynamic,
                        });
                    } else {
                        warn!(
                            "Duplicate local port {} ignored (line: {})",
                            local_port, line
                        );
                    }
                }
                Err(_) => {
                    warn!("Skipping invalid dynamic tunnel line: {}", line);
                }
            }
            continue;
        }

        let parts: Vec<&str> = line.split(';').collect();
        if parts.len() == 2 && (parts[1].eq_ignore_ascii_case("D")) {
            let local_port: u16 = parts[0]
                .parse()
                .with_context(|| format!("invalid local port in line: {}", line))?;
            if used_ports.insert(local_port) {
                res.push(TunnelCfg {
                    local_port,
                    kind: TunnelKind::Dynamic,
                });
            } else {
                warn!(
                    "Duplicate local port {} ignored (line: {})",
                    local_port, line
                );
            }
            continue;
        }

        if parts.len() == 2 {
            let local_port: u16 = parts[0]
                .parse()
                .with_context(|| format!("invalid local port in line: {}", line))?;
            let dst = parts[1];
            let (host, port) = parse_host_port(dst)
                .with_context(|| format!("invalid remote host:port in line: {}", line))?;
            if used_ports.insert(local_port) {
                res.push(TunnelCfg {
                    local_port,
                    kind: TunnelKind::Static {
                        remote_host: host.to_string(),
                        remote_port: port,
                    },
                });
            } else {
                warn!(
                    "Duplicate local port {} ignored (line: {})",
                    local_port, line
                );
            }
        } else {
            warn!("Skipping invalid tunnel line: {}", line);
        }
    }
    info!("Loaded {} tunnels", res.len());
    Ok(res)
}

fn parse_host_port(s: &str) -> Result<(&str, u16)> {
    let mut it = s.rsplitn(2, ':');
    let port_str = it.next().ok_or_else(|| anyhow::anyhow!("missing port"))?;
    let host = it.next().ok_or_else(|| anyhow::anyhow!("missing host"))?;
    let port: u16 = port_str.parse()?;
    Ok((host, port))
}

fn run_tunnel(args: &Args, t: &TunnelCfg, shutdown: Arc<AtomicBool>) -> Result<()> {
    let bind_addr = format!("127.0.0.1:{}", t.local_port);

    // Try to bind the local port, optionally waiting if it's temporarily busy.
    let bind_deadline = if args.bind_wait == 0 {
        None
    } else {
        Some(Instant::now() + Duration::from_secs(args.bind_wait))
    };
    let mut warned = false;
    let listener = loop {
        match TcpListener::bind(&bind_addr) {
            Ok(l) => break l,
            Err(e) => {
                if e.kind() == io::ErrorKind::AddrInUse {
                    if let Some(deadline) = bind_deadline {
                        if Instant::now() < deadline && !shutdown.load(Ordering::SeqCst) {
                            if !warned {
                                warn!(
                                    "Port {} is busy; will wait up to {}s for it to become free. You can identify the owner with: netstat -ano | findstr :{}",
                                    t.local_port, args.bind_wait, t.local_port
                                );
                                warned = true;
                            }
                            thread::sleep(Duration::from_millis(250));
                            continue;
                        }
                    }
                    anyhow::bail!(
                        "failed to bind local port {}: {}\nThe port is already in use. On Windows, run:\n  netstat -ano | findstr :{}\nthen:\n  Get-Process -Id <PID>\nClose the conflicting process or change the local port in tunnels.csv.",
                        t.local_port, e, t.local_port
                    );
                } else {
                    return Err(anyhow::Error::new(e))
                        .with_context(|| format!("failed to bind local port {}", t.local_port));
                }
            }
        }
    };

    match &t.kind {
        TunnelKind::Static {
            remote_host,
            remote_port,
        } => {
            info!(
                "Listening on {} and forwarding via SSH {}:{} to {}:{}",
                bind_addr, args.host, args.port, remote_host, remote_port
            );
            // Explicit startup log (helps grepping for lifecycle events)
            info!(
                "Tunnel started: local {} -> {}:{} (via {}:{})",
                bind_addr, remote_host, remote_port, args.host, args.port
            );
        }
        TunnelKind::Dynamic => {
            info!(
                "Listening on {} for dynamic SOCKS5 forwarding via SSH {}:{}",
                bind_addr, args.host, args.port
            );
            // Explicit startup log for dynamic SOCKS
            info!(
                "Tunnel started: dynamic SOCKS5 on {} (via {}:{})",
                bind_addr, args.host, args.port
            );
            // Hand off to a single-threaded multiplexing event loop that keeps one SSH session
            // and opens a new direct-tcpip channel per SOCKS connection.
            return run_dynamic_socks5_loop(args, t, shutdown, listener);
        }
    }
    listener.set_nonblocking(true).ok();

    while !shutdown.load(Ordering::SeqCst) {
        match listener.accept() {
            Ok((client_stream, addr)) => {
                info!("Incoming connection from {} to {}", addr, bind_addr);
                let a = args.clone();
                let tc = t.clone();
                let s = shutdown.clone();
                thread::spawn(move || {
                    match &tc.kind {
                        TunnelKind::Static {
                            remote_host,
                            remote_port,
                        } => {
                            if let Err(e) = handle_static_connection(
                                &a,
                                remote_host,
                                *remote_port,
                                client_stream,
                                s,
                            ) {
                                error!("Static connection handling error: {:#}", e);
                            }
                        }
                        TunnelKind::Dynamic => {
                            // Should never hit: dynamic mode handled by run_dynamic_socks5_loop
                            if let Err(e) = handle_dynamic_connection(&a, client_stream, s) {
                                error!("Dynamic connection handling error: {:#}", e);
                            }
                        }
                    }
                });
            }
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(100));
            }
            Err(e) => {
                error!("Accept error on {}: {}", bind_addr, e);
                thread::sleep(Duration::from_millis(500));
            }
        }
    }

    info!("Shutting down listener on {}", bind_addr);
    // Explicit shutdown log
    info!("Tunnel stopped: local {}", bind_addr);
    Ok(())
}

fn ssh_connect(args: &Args) -> Result<Session> {
    // Resolve and connect with a finite CONNECT timeout, but keep the established
    // TCP stream in blocking mode without per-IO timeouts to avoid spurious
    // disconnects during long-lived tunnels.
    let addr_str = format!("{}:{}", args.host, args.port);
    info!(
        "Attempting SSH connection to {} as {} with timeout {:?}",
        addr_str,
        args.user,
        Duration::from_secs(args.timeout)
    );
    let mut last_err: Option<io::Error> = None;
    let connect_timeout = Duration::from_secs(args.timeout);
    let mut tcp_opt: Option<TcpStream> = None;

    // Try all resolved addresses until one works within the timeout
    for addr in addr_str
        .to_socket_addrs()
        .with_context(|| format!("failed to resolve SSH server address {}", addr_str))?
    {
        match TcpStream::connect_timeout(&addr, connect_timeout) {
            Ok(s) => {
                tcp_opt = Some(s);
                break;
            }
            Err(e) => {
                last_err = Some(e);
                continue;
            }
        }
    }

    let mut tcp = match tcp_opt {
        Some(s) => s,
        None => {
            return Err(anyhow::anyhow!(
                "failed to connect to SSH server at {} within {:?}: {}",
                addr_str,
                connect_timeout,
                last_err
                    .map(|e| e.to_string())
                    .unwrap_or_else(|| "unknown error".to_string())
            ))
        }
    };

    // Ensure blocking mode; do not set per-read/write timeouts.
    let _ = tcp.set_nonblocking(false);

    let mut session = Session::new().context("failed to create SSH session")?;
    session.set_tcp_stream(tcp);

    // Disable libssh2 operation timeout (0 = infinite) to prevent idle tunnels from timing out.
    session.set_timeout(0);

    session.handshake().context("SSH handshake failed")?;
    session
        .userauth_password(&args.user, &args.password)
        .context("SSH authentication failed")?;
    if !session.authenticated() {
        anyhow::bail!("SSH authentication rejected");
    }
    // Configure keepalive if requested
    if args.keepalive == 0 {
        // disable explicit keepalives
        let _ = session.set_keepalive(false, 0);
    } else {
        let _ = session.set_keepalive(true, args.keepalive);
    }
    info!(
        "SSH connection established to {}:{} as {}",
        args.host, args.port, args.user
    );
    Ok(session)
}

fn ssh_connect_with_retry(args: &Args, shutdown: Arc<AtomicBool>) -> Result<Session> {
    let mut attempt: u32 = 0;
    loop {
        if shutdown.load(Ordering::SeqCst) {
            anyhow::bail!("Shutdown requested");
        }
        attempt = attempt.saturating_add(1);
        match ssh_connect(args) {
            Ok(sess) => {
                if attempt > 1 {
                    info!("SSH reconnected after {} attempt(s)", attempt);
                }
                return Ok(sess);
            }
            Err(e) => {
                let max = if args.retries == 0 {
                    "∞".to_string()
                } else {
                    args.retries.to_string()
                };
                warn!("SSH connect attempt {} / {} failed: {}", attempt, max, e);
                if args.retries != 0 && attempt >= args.retries {
                    error!("SSH connection failed after {} attempts: {}", attempt, e);
                    return Err(anyhow::anyhow!(
                        "SSH connection failed after {} attempts: {}",
                        attempt,
                        e
                    ));
                }
                // Sleep before retry, checking for shutdown periodically
                let total_ms = args.retry_interval.saturating_mul(1000);
                let mut waited_ms = 0u64;
                while waited_ms < total_ms {
                    if shutdown.load(Ordering::SeqCst) {
                        anyhow::bail!("Shutdown requested");
                    }
                    let step_ms = 250u64.min(total_ms - waited_ms);
                    thread::sleep(Duration::from_millis(step_ms));
                    waited_ms += step_ms;
                }
            }
        }
    }
}

fn handle_static_connection(
    args: &Args,
    remote_host: &str,
    remote_port: u16,
    mut client_stream: TcpStream,
    shutdown: Arc<AtomicBool>,
) -> Result<()> {
    // Use a single-threaded, non-blocking pump to avoid concurrent libssh2 channel access deadlocks.
    // Make client socket non-blocking and disable Nagle for lower latency.
    let _ = client_stream.set_nonblocking(true);
    client_stream.set_nodelay(true).ok();

    // SSH connect with retry
    let mut session = ssh_connect_with_retry(args, shutdown.clone())?;

    // Open direct-tcpip channel to target (blocking open), then switch the session to non-blocking I/O
    let mut channel = session
        .channel_direct_tcpip(remote_host, remote_port, None)
        .with_context(|| {
            format!(
                "failed to open direct-tcpip channel to {}:{}",
                remote_host, remote_port
            )
        })?;
    session.set_blocking(false);

    info!(
        "Started static tunnel relay: client -> {}:{} and back",
        remote_host, remote_port
    );

    // Pending write buffers (when peer's write would block)
    let mut pending_c2s: Option<(Vec<u8>, usize)> = None; // (buffer, next_index)
    let mut pending_s2c: Option<(Vec<u8>, usize)> = None;

    let mut client_closed = false; // client half-closed (read EOF)
    let mut server_closed = false; // server/channel EOF observed

    let mut bytes_c2s: u64 = 0;
    let mut bytes_s2c: u64 = 0;

    let mut buf = vec![0u8; 16 * 1024];

    // Pump loop
    loop {
        if shutdown.load(Ordering::SeqCst) {
            break;
        }
        let mut progressed = false;

        // Flush pending client->server data first
        if let Some((ref data, ref mut pos)) = pending_c2s {
            if *pos < data.len() {
                match channel.write(&data[*pos..]) {
                    Ok(w) if w > 0 => {
                        *pos += w;
                        bytes_c2s = bytes_c2s.saturating_add(w as u64);
                        progressed = true;
                    }
                    Ok(_) => {}
                    Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {}
                    Err(e) => return Err(e.into()),
                }
            }
            if *pos >= data.len() {
                pending_c2s = None;
            }
        } else if !client_closed {
            // Read from client and write to server/channel
            match client_stream.read(&mut buf) {
                Ok(0) => {
                    // Client closed its write side; send EOF to remote
                    client_closed = true;
                    let _ = channel.send_eof();
                    progressed = true;
                }
                Ok(n) => {
                    let mut written = 0usize;
                    while written < n {
                        match channel.write(&buf[written..n]) {
                            Ok(w) if w > 0 => {
                                written += w;
                                bytes_c2s = bytes_c2s.saturating_add(w as u64);
                                progressed = true;
                            }
                            Ok(_) => {}
                            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                                // Save remainder for later attempts
                                pending_c2s = Some((buf[..n].to_vec(), written));
                                break;
                            }
                            Err(e) => return Err(e.into()),
                        }
                    }
                }
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {}
                Err(e) => return Err(e.into()),
            }
        }

        // Flush pending server->client data first
        if let Some((ref data, ref mut pos)) = pending_s2c {
            if *pos < data.len() {
                match client_stream.write(&data[*pos..]) {
                    Ok(w) if w > 0 => {
                        *pos += w;
                        bytes_s2c = bytes_s2c.saturating_add(w as u64);
                        progressed = true;
                    }
                    Ok(_) => {}
                    Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {}
                    Err(e) => return Err(e.into()),
                }
            }
            if *pos >= data.len() {
                pending_s2c = None;
            }
        } else if !server_closed {
            // Read from server/channel and write to client
            match channel.read(&mut buf) {
                Ok(0) => {
                    server_closed = true;
                    progressed = true;
                }
                Ok(n) => {
                    let mut written = 0usize;
                    while written < n {
                        match client_stream.write(&buf[written..n]) {
                            Ok(w) if w > 0 => {
                                written += w;
                                bytes_s2c = bytes_s2c.saturating_add(w as u64);
                                progressed = true;
                            }
                            Ok(_) => {}
                            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                                pending_s2c = Some((buf[..n].to_vec(), written));
                                break;
                            }
                            Err(e) => return Err(e.into()),
                        }
                    }
                }
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {}
                Err(e) => return Err(e.into()),
            }
        }

        // Exit once both halves are closed and nothing is pending
        if client_closed && server_closed && pending_c2s.is_none() && pending_s2c.is_none() {
            break;
        }

        if !progressed {
            // Avoid busy spin
            thread::sleep(Duration::from_millis(10));
        }
    }

    info!(
        "Static tunnel closed. Transferred: client->server: {} bytes, server->client: {} bytes",
        bytes_c2s, bytes_s2c
    );

    // Attempt to close channel gracefully
    if let Err(e) = channel.flush() {
        warn!("flush error: {}", e);
    }
    if let Err(e) = channel.close() {
        warn!("channel close error: {}", e);
    }

    Ok(())
}

fn handle_dynamic_connection(
    args: &Args,
    mut client_stream: TcpStream,
    _shutdown: Arc<AtomicBool>,
) -> Result<()> {
    // Legacy single-connection handler (blocking). Kept for reference; not used in multiplexing mode.
    // Accepted sockets inherit nonblocking from the listener; switch back to blocking for blocking-style I/O
    let _ = client_stream.set_nonblocking(false);
    client_stream.set_nodelay(true).ok();

    // SOCKS5 handshake (RFC 1928)
    let mut buf = [0u8; 262]; // enough for greeting and domain name
                              // Read VER, NMETHODS
    client_stream
        .read_exact(&mut buf[..2])
        .context("failed to read SOCKS5 greeting header")?;
    if buf[0] != 0x05 {
        anyhow::bail!("Unsupported SOCKS version: {}", buf[0]);
    }
    let nmethods = buf[1] as usize;
    if nmethods == 0 {
        anyhow::bail!("SOCKS5 no methods provided");
    }
    client_stream
        .read_exact(&mut buf[..nmethods])
        .context("failed to read SOCKS5 methods")?;
    // We accept 'no authentication' (0x00)
    client_stream
        .write_all(&[0x05, 0x00])
        .context("failed to write SOCKS5 method selection")?;

    // Read request: VER, CMD, RSV, ATYP
    client_stream
        .read_exact(&mut buf[..4])
        .context("failed to read SOCKS5 request header")?;
    if buf[0] != 0x05 {
        anyhow::bail!("Invalid SOCKS5 request version");
    }
    let cmd = buf[1];
    if cmd != 0x01 {
        // CONNECT
        // reply: general failure
        let reply = [0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
        let _ = client_stream.write_all(&reply);
        anyhow::bail!("Unsupported SOCKS5 CMD: {}", cmd);
    }
    let atyp = buf[3];

    // Parse destination
    let (dest_host, dest_port): (String, u16) = match atyp {
        0x01 => {
            // IPv4
            client_stream
                .read_exact(&mut buf[..4])
                .context("failed to read IPv4 addr")?;
            let addr = format!("{}.{}.{}.{}", buf[0], buf[1], buf[2], buf[3]);
            client_stream
                .read_exact(&mut buf[..2])
                .context("failed to read port")?;
            let port = u16::from_be_bytes([buf[0], buf[1]]);
            (addr, port)
        }
        0x03 => {
            // DOMAIN
            client_stream
                .read_exact(&mut buf[..1])
                .context("failed to read domain length")?;
            let len = buf[0] as usize;
            client_stream
                .read_exact(&mut buf[..len])
                .context("failed to read domain bytes")?;
            let host = String::from_utf8_lossy(&buf[..len]).to_string();
            client_stream
                .read_exact(&mut buf[..2])
                .context("failed to read port")?;
            let port = u16::from_be_bytes([buf[0], buf[1]]);
            (host, port)
        }
        0x04 => {
            // IPv6
            let mut v6 = [0u8; 16];
            client_stream
                .read_exact(&mut v6)
                .context("failed to read IPv6 addr")?;
            let addr = std::net::Ipv6Addr::from(v6).to_string();
            client_stream
                .read_exact(&mut buf[..2])
                .context("failed to read port")?;
            let port = u16::from_be_bytes([buf[0], buf[1]]);
            (addr, port)
        }
        _ => {
            // reply: address type not supported
            let reply = [0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
            let _ = client_stream.write_all(&reply);
            anyhow::bail!("Unsupported ATYP: {}", atyp);
        }
    };

    // Connect over SSH to dest (with retry)
    let session = match ssh_connect_with_retry(args, _shutdown.clone()) {
        Ok(s) => s,
        Err(e) => {
            // reply: general failure
            let reply = [0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
            let _ = client_stream.write_all(&reply);
            return Err(e);
        }
    };
    let mut channel = match session.channel_direct_tcpip(&dest_host, dest_port, None) {
        Ok(c) => c,
        Err(e) => {
            // reply: connection refused
            let reply = [0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
            let _ = client_stream.write_all(&reply);
            return Err(e.into());
        }
    };

    // Send success reply (bound addr/port set to 0.0.0.0:0)
    let success = [0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
    client_stream
        .write_all(&success)
        .context("failed to write SOCKS5 success reply")?;

    // Relay via two threads (legacy)
    let mut server_read = channel.stream(0);
    let mut server_write = channel.stream(0);
    let mut channel_clone = channel.stream(0);
    let (mut stream_read, mut stream_write) = match client_stream.try_clone() {
        Ok(s) => (client_stream, s),
        Err(e) => return Err(e.into()),
    };

    info!("Started dynamic SOCKS relay to {}:{}", dest_host, dest_port);

    let thread_c2s = thread::spawn(move || io::copy(&mut stream_read, &mut channel_clone));
    let thread_s2c = thread::spawn(move || io::copy(&mut server_read, &mut stream_write));

    let bytes_c2s = match thread_c2s.join() {
        Ok(Ok(n)) => n,
        Ok(Err(e)) => {
            warn!("client->server relay error: {}", e);
            0
        }
        Err(_) => {
            warn!("client->server relay panicked");
            0
        }
    };
    let bytes_s2c = match thread_s2c.join() {
        Ok(Ok(n)) => n,
        Ok(Err(e)) => {
            warn!("server->client relay error: {}", e);
            0
        }
        Err(_) => {
            warn!("server->client relay panicked");
            0
        }
    };

    info!("Dynamic SOCKS relay closed for {}:{}. Transferred: client->server: {} bytes, server->client: {} bytes", dest_host, dest_port, bytes_c2s, bytes_s2c);

    if let Err(e) = server_write.flush() {
        warn!("flush error: {}", e);
    }
    if let Err(e) = channel.close() {
        warn!("channel close error: {}", e);
    }

    Ok(())
}

fn run_dynamic_socks5_loop(
    args: &Args,
    t: &TunnelCfg,
    shutdown: Arc<AtomicBool>,
    listener: TcpListener,
) -> Result<()> {
    // Single-threaded event loop with a single SSH session and many channels.
    use io::ErrorKind;

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum HsState {
        ReadGreeting2,
        ReadMethods { n: usize, read: usize },
        SendMethodSel { wrote: usize },
        ReadReq4,
        ReadAddr { atyp: u8, need: usize }, // for domain, need expands after first len byte
        OpenChannel,
        SendSuccess { wrote: usize },
        Relay,
        Closing,
    }

    struct DynClient {
        id: u64,
        stream: TcpStream,
        addr: std::net::SocketAddr,
        hs_state: HsState,
        hs_buf: Vec<u8>,
        write_buf: Option<(Vec<u8>, usize)>, // pending write to client during handshake
        dest_host: Option<String>,
        dest_port: Option<u16>,
        channel: Option<ssh2::Channel>,
        // relay state
        pending_c2s: Option<(Vec<u8>, usize)>,
        pending_s2c: Option<(Vec<u8>, usize)>,
        client_closed: bool,
        server_closed: bool,
        bytes_c2s: u64,
        bytes_s2c: u64,
        buf: Vec<u8>,
    }

    impl DynClient {
        fn new(id: u64, stream: TcpStream, addr: std::net::SocketAddr) -> Self {
            Self {
                id,
                stream,
                addr,
                hs_state: HsState::ReadGreeting2,
                hs_buf: Vec::with_capacity(512),
                write_buf: None,
                dest_host: None,
                dest_port: None,
                channel: None,
                pending_c2s: None,
                pending_s2c: None,
                client_closed: false,
                server_closed: false,
                bytes_c2s: 0,
                bytes_s2c: 0,
                buf: vec![0u8; 16 * 1024],
            }
        }
    }

    let bind_addr = format!("127.0.0.1:{}", t.local_port);
    let _ = listener.set_nonblocking(true);

    // Establish SSH session once
    let mut session = ssh_connect_with_retry(args, shutdown.clone())?;
    session.set_blocking(false);
    let mut last_keepalive = Instant::now();
    info!(
        "Dynamic: SSH session up; entering event loop on {}",
        bind_addr
    );

    let mut clients: Vec<DynClient> = Vec::new();
    let mut next_id: u64 = 1;

    loop {
        if shutdown.load(Ordering::SeqCst) {
            break;
        }

        // Periodic SSH keepalive/health check and auto-reconnect
        if args.keepalive > 0
            && last_keepalive.elapsed() >= Duration::from_secs(args.keepalive as u64)
        {
            match session.keepalive_send() {
                Ok(_) => {
                    last_keepalive = Instant::now();
                }
                Err(e) => {
                    warn!(
                        "Dynamic: SSH keepalive failed: {}. Reconnecting session...",
                        e
                    );
                    // Mark existing channel-based clients for closing; pending OpenChannel can retry
                    for c in clients.iter_mut() {
                        if c.channel.is_some() {
                            c.hs_state = HsState::Closing;
                        }
                    }
                    // Reconnect session
                    session = ssh_connect_with_retry(args, shutdown.clone())?;
                    session.set_blocking(false);
                    last_keepalive = Instant::now();
                    info!("Dynamic: SSH session re-established after keepalive failure");
                }
            }
        }

        // Accept as many new connections as available
        loop {
            match listener.accept() {
                Ok((mut s, addr)) => {
                    let _ = s.set_nonblocking(true);
                    s.set_nodelay(true).ok();
                    let id = next_id;
                    next_id += 1;
                    info!(
                        "Dynamic: accepted {} -> {} as client#{}",
                        addr, bind_addr, id
                    );
                    clients.push(DynClient::new(id, s, addr));
                }
                Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                Err(e) => {
                    warn!("Dynamic: accept error on {}: {}", bind_addr, e);
                    break;
                }
            }
        }

        let mut progressed = false;
        let mut to_remove: Vec<usize> = Vec::new();

        for (idx, c) in clients.iter_mut().enumerate() {
            // Handshake progression until Relay
            match c.hs_state {
                HsState::ReadGreeting2 => {
                    // Need 2 bytes
                    let mut temp = [0u8; 64];
                    match c.stream.read(&mut temp) {
                        Ok(0) => {
                            c.hs_state = HsState::Closing;
                        }
                        Ok(n) => {
                            c.hs_buf.extend_from_slice(&temp[..n]);
                            progressed = true;
                        }
                        Err(e) if e.kind() == ErrorKind::WouldBlock => {}
                        Err(e) => {
                            warn!("client#{} read err: {}", c.id, e);
                            c.hs_state = HsState::Closing;
                        }
                    }
                    if c.hs_buf.len() >= 2 {
                        if c.hs_buf[0] != 0x05 {
                            warn!("client#{} unsupported SOCKS version {}", c.id, c.hs_buf[0]);
                            c.hs_state = HsState::Closing;
                        } else {
                            let n = c.hs_buf[1] as usize;
                            c.hs_buf.drain(0..2);
                            c.hs_state = HsState::ReadMethods { n, read: 0 };
                        }
                    }
                }
                HsState::ReadMethods { n, read } => {
                    if read < n {
                        let mut temp = [0u8; 256];
                        match c.stream.read(&mut temp) {
                            Ok(0) => {
                                c.hs_state = HsState::Closing;
                            }
                            Ok(m) => {
                                c.hs_buf.extend_from_slice(&temp[..m]);
                                progressed = true;
                            }
                            Err(e) if e.kind() == ErrorKind::WouldBlock => {}
                            Err(e) => {
                                warn!("client#{} read err: {}", c.id, e);
                                c.hs_state = HsState::Closing;
                            }
                        }
                    }
                    if c.hs_buf.len() >= n - read {
                        // consume methods
                        let take = n - read;
                        c.hs_buf.drain(0..take);
                        c.hs_state = HsState::SendMethodSel { wrote: 0 };
                        c.write_buf = Some((vec![0x05, 0x00], 0));
                    }
                }
                HsState::SendMethodSel { wrote } => {
                    if let Some((ref data, ref mut pos)) = c.write_buf {
                        match c.stream.write(&data[*pos..]) {
                            Ok(w) if w > 0 => {
                                *pos += w;
                                progressed = true;
                            }
                            Ok(_) => {}
                            Err(e) if e.kind() == ErrorKind::WouldBlock => {}
                            Err(e) => {
                                warn!("client#{} write err: {}", c.id, e);
                                c.hs_state = HsState::Closing;
                            }
                        }
                        if *pos >= data.len() {
                            c.write_buf = None;
                            c.hs_state = HsState::ReadReq4;
                        }
                    } else {
                        // should not happen
                        c.hs_state = HsState::ReadReq4;
                    }
                }
                HsState::ReadReq4 => {
                    let mut temp = [0u8; 64];
                    match c.stream.read(&mut temp) {
                        Ok(0) => {
                            c.hs_state = HsState::Closing;
                        }
                        Ok(n) => {
                            c.hs_buf.extend_from_slice(&temp[..n]);
                            progressed = true;
                        }
                        Err(e) if e.kind() == ErrorKind::WouldBlock => {}
                        Err(e) => {
                            warn!("client#{} read err: {}", c.id, e);
                            c.hs_state = HsState::Closing;
                        }
                    }
                    if c.hs_buf.len() >= 4 {
                        let ver = c.hs_buf[0];
                        let cmd = c.hs_buf[1];
                        let _rsv = c.hs_buf[2];
                        let atyp = c.hs_buf[3];
                        c.hs_buf.drain(0..4);
                        if ver != 0x05 || cmd != 0x01 {
                            // reply general failure
                            c.write_buf = Some((vec![0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0], 0));
                            c.hs_state = HsState::Closing;
                        } else {
                            let need = match atyp {
                                0x01 => 4 + 2,
                                0x03 => 1,
                                0x04 => 16 + 2,
                                _ => 0,
                            };
                            if need == 0 {
                                c.write_buf =
                                    Some((vec![0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0], 0));
                                c.hs_state = HsState::Closing;
                            } else {
                                c.hs_state = HsState::ReadAddr { atyp, need };
                            }
                        }
                    }
                }
                HsState::ReadAddr { atyp, need } => {
                    // read into hs_buf
                    let mut temp = [0u8; 512];
                    match c.stream.read(&mut temp) {
                        Ok(0) => {
                            c.hs_state = HsState::Closing;
                        }
                        Ok(n) => {
                            c.hs_buf.extend_from_slice(&temp[..n]);
                            progressed = true;
                        }
                        Err(e) if e.kind() == ErrorKind::WouldBlock => {}
                        Err(e) => {
                            warn!("client#{} read err: {}", c.id, e);
                            c.hs_state = HsState::Closing;
                        }
                    }
                    if c.hs_buf.len() >= need {
                        match atyp {
                            0x01 => {
                                // IPv4 + port
                                if c.hs_buf.len() >= 6 {
                                    let host = format!(
                                        "{}.{}.{}.{}",
                                        c.hs_buf[0], c.hs_buf[1], c.hs_buf[2], c.hs_buf[3]
                                    );
                                    let port = u16::from_be_bytes([c.hs_buf[4], c.hs_buf[5]]);
                                    c.hs_buf.drain(0..6);
                                    c.dest_host = Some(host);
                                    c.dest_port = Some(port);
                                    c.hs_state = HsState::OpenChannel;
                                }
                            }
                            0x03 => {
                                // DOMAIN
                                // need was at least 1 initially
                                let len = c.hs_buf[0] as usize;
                                if need == 1 {
                                    // expand requirement
                                    let new_need = 1 + len + 2;
                                    c.hs_state = HsState::ReadAddr {
                                        atyp,
                                        need: new_need,
                                    };
                                } else if c.hs_buf.len() >= 1 + len + 2 {
                                    let host =
                                        String::from_utf8_lossy(&c.hs_buf[1..1 + len]).to_string();
                                    let port = u16::from_be_bytes([
                                        c.hs_buf[1 + len],
                                        c.hs_buf[1 + len + 1],
                                    ]);
                                    c.hs_buf.drain(0..(1 + len + 2));
                                    c.dest_host = Some(host);
                                    c.dest_port = Some(port);
                                    c.hs_state = HsState::OpenChannel;
                                }
                            }
                            0x04 => {
                                // IPv6 + port
                                if c.hs_buf.len() >= 18 {
                                    let mut v6 = [0u8; 16];
                                    v6.copy_from_slice(&c.hs_buf[0..16]);
                                    let host = std::net::Ipv6Addr::from(v6).to_string();
                                    let port = u16::from_be_bytes([c.hs_buf[16], c.hs_buf[17]]);
                                    c.hs_buf.drain(0..18);
                                    c.dest_host = Some(host);
                                    c.dest_port = Some(port);
                                    c.hs_state = HsState::OpenChannel;
                                }
                            }
                            _ => {
                                c.write_buf =
                                    Some((vec![0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0], 0));
                                c.hs_state = HsState::Closing;
                            }
                        }
                    }
                }
                HsState::OpenChannel => {
                    let host = match &c.dest_host {
                        Some(h) => h.clone(),
                        None => {
                            c.hs_state = HsState::Closing;
                            continue;
                        }
                    };
                    let port = match c.dest_port {
                        Some(p) => p,
                        None => {
                            c.hs_state = HsState::Closing;
                            continue;
                        }
                    };
                    // Perform channel open in blocking mode to avoid libssh2 EAGAIN bookkeeping here
                    session.set_blocking(true);
                    let mut open_res = session.channel_direct_tcpip(&host, port, None);
                    session.set_blocking(false);
                    if open_res.is_err() {
                        warn!("Dynamic: client#{} channel open to {}:{} failed; attempting SSH session reconnect and retry...", c.id, host, port);
                        // Reconnect SSH session and retry once
                        match ssh_connect_with_retry(args, shutdown.clone()) {
                            Ok(mut new_sess) => {
                                new_sess.set_blocking(false);
                                session = new_sess; // replace session
                                                    // Retry open (in blocking mode for the call)
                                session.set_blocking(true);
                                open_res = session.channel_direct_tcpip(&host, port, None);
                                session.set_blocking(false);
                            }
                            Err(e) => {
                                warn!("Dynamic: SSH session reconnect failed while opening channel for client#{}: {}", c.id, e);
                            }
                        }
                    }
                    match open_res {
                        Ok(ch) => {
                            c.channel = Some(ch);
                            // success reply: bound addr 0.0.0.0:0
                            c.write_buf = Some((vec![0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0], 0));
                            c.hs_state = HsState::SendSuccess { wrote: 0 };
                            progressed = true;
                            info!("Dynamic: client#{} connected to {}:{}", c.id, host, port);
                        }
                        Err(e) => {
                            warn!(
                                "Dynamic: client#{} channel open to {}:{} failed after retry: {}",
                                c.id, host, port, e
                            );
                            c.write_buf = Some((vec![0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0], 0));
                            c.hs_state = HsState::Closing;
                        }
                    }
                }
                HsState::SendSuccess { wrote: _ } => {
                    if let Some((ref data, ref mut pos)) = c.write_buf {
                        match c.stream.write(&data[*pos..]) {
                            Ok(w) if w > 0 => {
                                *pos += w;
                                progressed = true;
                            }
                            Ok(_) => {}
                            Err(e) if e.kind() == ErrorKind::WouldBlock => {}
                            Err(e) => {
                                warn!("client#{} write err: {}", c.id, e);
                                c.hs_state = HsState::Closing;
                            }
                        }
                        if *pos >= data.len() {
                            c.write_buf = None;
                            c.hs_state = HsState::Relay;
                        }
                    } else {
                        c.hs_state = HsState::Relay;
                    }
                }
                HsState::Relay => {
                    let ch = match c.channel.as_mut() {
                        Some(ch) => ch,
                        None => {
                            c.hs_state = HsState::Closing;
                            continue;
                        }
                    };

                    // First, flush any pending client->server
                    if let Some((ref data, ref mut pos)) = c.pending_c2s {
                        if *pos < data.len() {
                            match ch.write(&data[*pos..]) {
                                Ok(w) if w > 0 => {
                                    *pos += w;
                                    c.bytes_c2s = c.bytes_c2s.saturating_add(w as u64);
                                    progressed = true;
                                }
                                Ok(_) => {}
                                Err(e) if e.kind() == ErrorKind::WouldBlock => {}
                                Err(e) => {
                                    warn!("client#{} ch.write err: {}", c.id, e);
                                    c.hs_state = HsState::Closing;
                                    continue;
                                }
                            }
                        }
                        if *pos >= data.len() {
                            c.pending_c2s = None;
                        }
                    } else if !c.client_closed {
                        match c.stream.read(&mut c.buf) {
                            Ok(0) => {
                                c.client_closed = true;
                                let _ = ch.send_eof();
                                progressed = true;
                            }
                            Ok(n) => {
                                let mut written = 0usize;
                                while written < n {
                                    match ch.write(&c.buf[written..n]) {
                                        Ok(w) if w > 0 => {
                                            written += w;
                                            c.bytes_c2s = c.bytes_c2s.saturating_add(w as u64);
                                            progressed = true;
                                        }
                                        Ok(_) => {}
                                        Err(e) if e.kind() == ErrorKind::WouldBlock => {
                                            c.pending_c2s = Some((c.buf[..n].to_vec(), written));
                                            break;
                                        }
                                        Err(e) => {
                                            warn!("client#{} ch.write err: {}", c.id, e);
                                            c.hs_state = HsState::Closing;
                                            break;
                                        }
                                    }
                                }
                            }
                            Err(e) if e.kind() == ErrorKind::WouldBlock => {}
                            Err(e) => {
                                warn!("client#{} read err: {}", c.id, e);
                                c.hs_state = HsState::Closing;
                            }
                        }
                    }

                    // Then, flush any pending server->client
                    if let Some((ref data, ref mut pos)) = c.pending_s2c {
                        if *pos < data.len() {
                            match c.stream.write(&data[*pos..]) {
                                Ok(w) if w > 0 => {
                                    *pos += w;
                                    c.bytes_s2c = c.bytes_s2c.saturating_add(w as u64);
                                    progressed = true;
                                }
                                Ok(_) => {}
                                Err(e) if e.kind() == ErrorKind::WouldBlock => {}
                                Err(e) => {
                                    warn!("client#{} write err: {}", c.id, e);
                                    c.hs_state = HsState::Closing;
                                    continue;
                                }
                            }
                        }
                        if *pos >= data.len() {
                            c.pending_s2c = None;
                        }
                    } else if !c.server_closed {
                        match ch.read(&mut c.buf) {
                            Ok(0) => {
                                c.server_closed = true;
                                progressed = true;
                            }
                            Ok(n) => {
                                let mut written = 0usize;
                                while written < n {
                                    match c.stream.write(&c.buf[written..n]) {
                                        Ok(w) if w > 0 => {
                                            written += w;
                                            c.bytes_s2c = c.bytes_s2c.saturating_add(w as u64);
                                            progressed = true;
                                        }
                                        Ok(_) => {}
                                        Err(e) if e.kind() == ErrorKind::WouldBlock => {
                                            c.pending_s2c = Some((c.buf[..n].to_vec(), written));
                                            break;
                                        }
                                        Err(e) => {
                                            warn!("client#{} write err: {}", c.id, e);
                                            c.hs_state = HsState::Closing;
                                            break;
                                        }
                                    }
                                }
                            }
                            Err(e) if e.kind() == ErrorKind::WouldBlock => {}
                            Err(e) => {
                                warn!("client#{} ch.read err: {}", c.id, e);
                                c.hs_state = HsState::Closing;
                            }
                        }
                    }

                    if c.client_closed
                        && c.server_closed
                        && c.pending_c2s.is_none()
                        && c.pending_s2c.is_none()
                    {
                        c.hs_state = HsState::Closing;
                    }
                }
                HsState::Closing => {
                    // Attempt to close
                    if let Some(mut ch) = c.channel.take() {
                        if let Err(e) = ch.flush() {
                            let _ = e;
                        }
                        if let Err(e) = ch.close() {
                            let _ = e;
                        }
                    }
                    info!(
                        "Dynamic: client#{} closed. Bytes c2s={} s2c={}",
                        c.id, c.bytes_c2s, c.bytes_s2c
                    );
                    to_remove.push(idx);
                }
            }
        }

        // Remove closed clients from the vector (from back to front)
        if !to_remove.is_empty() {
            to_remove.sort_unstable();
            to_remove.drain(..).rev().for_each(|i| {
                clients.remove(i);
            });
            progressed = true;
        }

        if !progressed {
            thread::sleep(Duration::from_millis(10));
        }
    }

    // Shutdown: close all clients and session
    for mut c in clients.into_iter() {
        if let Some(mut ch) = c.channel.take() {
            let _ = ch.flush();
            let _ = ch.close();
        }
        let _ = c.stream.shutdown(std::net::Shutdown::Both);
    }
    info!("Dynamic: listener {} shut down", bind_addr);
    // Explicit shutdown log for lifecycle clarity
    info!(
        "Tunnel stopped: dynamic SOCKS5 on {} (via {}:{})",
        bind_addr, args.host, args.port
    );
    Ok(())
}

#[cfg(test)]
mod tests;
