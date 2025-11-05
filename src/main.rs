use anyhow::{Context, Result};
use clap::Parser;
use ctrlc;
use env_logger;
use log::{error, info, warn};
use ssh2::Session;
use std::fs::File;
use std::io::{self, BufRead, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

#[derive(Parser, Debug, Clone)]
#[command(name = "metro", about = "Simple SSH tunneling tool (Rust edition)")]
struct Args {
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

    /// CSV list of tunnels. Supported formats per line:
    /// - "<local_port>;<remote_host>:<remote_port>" for static local forwarding
    /// - "D<local_port>" or "<local_port>;D" for dynamic SOCKS5 forwarding on <local_port>
    #[arg(long, value_name = "FILE")]
    list: PathBuf,
}

#[derive(Debug, Clone)]
enum TunnelKind {
    Static { remote_host: String, remote_port: u16 },
    Dynamic,
}

#[derive(Debug, Clone)]
struct TunnelCfg {
    local_port: u16,
    kind: TunnelKind,
}

fn main() -> Result<()> {
    env_logger::init();
    let args = Args::parse();

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
                    TunnelKind::Static { remote_host, remote_port } => {
                        error!("Tunnel {} -> {}:{} failed: {:#}", t.local_port, remote_host, remote_port, e);
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
    for line in reader.lines() {
        let line = line?;
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') { continue; }

        // Support formats:
        // 1) "<local_port>;<remote_host>:<remote_port>" (static)
        // 2) "D<port>" (dynamic SOCKS on <port>)
        // 3) "<local_port>;D" (dynamic SOCKS on <local_port>)
        if line.starts_with('D') || line.starts_with('d') {
            let port_str = &line[1..];
            match port_str.parse::<u16>() {
                Ok(local_port) => {
                    res.push(TunnelCfg { local_port, kind: TunnelKind::Dynamic });
                }
                Err(_) => {
                    warn!("Skipping invalid dynamic tunnel line: {}", line);
                }
            }
            continue;
        }

        let parts: Vec<&str> = line.split(';').collect();
        if parts.len() == 2 && (parts[1].eq_ignore_ascii_case("D")) {
            let local_port: u16 = parts[0].parse().with_context(|| format!("invalid local port in line: {}", line))?;
            res.push(TunnelCfg { local_port, kind: TunnelKind::Dynamic });
            continue;
        }

        if parts.len() == 2 {
            let local_port: u16 = parts[0].parse().with_context(|| format!("invalid local port in line: {}", line))?;
            let dst = parts[1];
            let (host, port) = parse_host_port(dst).with_context(|| format!("invalid remote host:port in line: {}", line))?;
            res.push(TunnelCfg { local_port, kind: TunnelKind::Static { remote_host: host.to_string(), remote_port: port } });
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
    let listener = TcpListener::bind(&bind_addr)
        .with_context(|| format!("failed to bind local port {}", t.local_port))?;
    match &t.kind {
        TunnelKind::Static { remote_host, remote_port } => {
            info!("Listening on {} and forwarding via SSH {}:{} to {}:{}", bind_addr, args.host, args.port, remote_host, remote_port);
        }
        TunnelKind::Dynamic => {
            info!("Listening on {} for dynamic SOCKS5 forwarding via SSH {}:{}", bind_addr, args.host, args.port);
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
                        TunnelKind::Static { remote_host, remote_port } => {
                            if let Err(e) = handle_static_connection(&a, remote_host, *remote_port, client_stream, s) {
                                error!("Static connection handling error: {:#}", e);
                            }
                        }
                        TunnelKind::Dynamic => {
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
    Ok(())
}

fn ssh_connect(args: &Args) -> Result<Session> {
    let ssh_address = format!("{}:{}", args.host, args.port);
    let mut tcp = TcpStream::connect(&ssh_address)
        .with_context(|| format!("failed to connect to SSH server at {}", ssh_address))?;
    tcp.set_read_timeout(Some(Duration::from_secs(args.timeout))).ok();
    tcp.set_write_timeout(Some(Duration::from_secs(args.timeout))).ok();

    let mut session = Session::new().context("failed to create SSH session")?;
    session.set_tcp_stream(tcp);
    session.set_timeout((args.timeout * 1000) as u32);
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
                if attempt > 1 { info!("SSH reconnected after {} attempt(s)", attempt); }
                return Ok(sess);
            }
            Err(e) => {
                let max = if args.retries == 0 { "∞".to_string() } else { args.retries.to_string() };
                warn!("SSH connect attempt {} / {} failed: {}", attempt, max, e);
                if args.retries != 0 && attempt >= args.retries {
                    return Err(anyhow::anyhow!("SSH connection failed after {} attempts: {}", attempt, e));
                }
                // Sleep before retry, checking for shutdown periodically
                let total_ms = args.retry_interval.saturating_mul(1000);
                let mut waited_ms = 0u64;
                while waited_ms < total_ms {
                    if shutdown.load(Ordering::SeqCst) { anyhow::bail!("Shutdown requested"); }
                    let step_ms = 250u64.min(total_ms - waited_ms);
                    thread::sleep(Duration::from_millis(step_ms));
                    waited_ms += step_ms;
                }
            }
        }
    }
}

fn handle_static_connection(args: &Args, remote_host: &str, remote_port: u16, mut client_stream: TcpStream, shutdown: Arc<AtomicBool>) -> Result<()> {
    client_stream.set_nodelay(true).ok();

    // SSH connect with retry
    let session = ssh_connect_with_retry(args, shutdown.clone())?;

    // Open direct-tcpip channel to target
    let mut channel = session
        .channel_direct_tcpip(remote_host, remote_port, None)
        .with_context(|| format!("failed to open direct-tcpip channel to {}:{}", remote_host, remote_port))?;

    // Bi-directional relay
    let mut server_read = channel.stream(0);
    let mut server_write = channel.stream(0);

    // client -> server
    let mut channel_clone = channel.stream(0);
    let (mut stream_read, mut stream_write) = match client_stream.try_clone() {
        Ok(s) => (client_stream, s),
        Err(e) => return Err(e.into()),
    };

    let thread1 = thread::spawn(move || io::copy(&mut stream_read, &mut channel_clone).map(|_| ()) );
    let thread2 = thread::spawn(move || io::copy(&mut server_read, &mut stream_write).map(|_| ()) );

    let _ = thread1.join();
    let _ = thread2.join();

    // Attempt to close channel gracefully
    if let Err(e) = server_write.flush() { warn!("flush error: {}", e); }
    if let Err(e) = channel.close() { warn!("channel close error: {}", e); }

    Ok(())
}

fn handle_dynamic_connection(args: &Args, mut client_stream: TcpStream, _shutdown: Arc<AtomicBool>) -> Result<()> {
    client_stream.set_nodelay(true).ok();

    // SOCKS5 handshake (RFC 1928)
    let mut buf = [0u8; 262]; // enough for greeting and domain name
    // Read VER, NMETHODS
    client_stream.read_exact(&mut buf[..2]).context("failed to read SOCKS5 greeting header")?;
    if buf[0] != 0x05 {
        anyhow::bail!("Unsupported SOCKS version: {}", buf[0]);
    }
    let nmethods = buf[1] as usize;
    if nmethods == 0 { anyhow::bail!("SOCKS5 no methods provided"); }
    client_stream.read_exact(&mut buf[..nmethods]).context("failed to read SOCKS5 methods")?;
    // We accept 'no authentication' (0x00)
    client_stream.write_all(&[0x05, 0x00]).context("failed to write SOCKS5 method selection")?;

    // Read request: VER, CMD, RSV, ATYP
    client_stream.read_exact(&mut buf[..4]).context("failed to read SOCKS5 request header")?;
    if buf[0] != 0x05 { anyhow::bail!("Invalid SOCKS5 request version"); }
    let cmd = buf[1];
    if cmd != 0x01 { // CONNECT
        // reply: general failure
        let reply = [0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
        let _ = client_stream.write_all(&reply);
        anyhow::bail!("Unsupported SOCKS5 CMD: {}", cmd);
    }
    let atyp = buf[3];

    // Parse destination
    let (dest_host, dest_port): (String, u16) = match atyp {
        0x01 => { // IPv4
            client_stream.read_exact(&mut buf[..4]).context("failed to read IPv4 addr")?;
            let addr = format!("{}.{}.{}.{}", buf[0], buf[1], buf[2], buf[3]);
            client_stream.read_exact(&mut buf[..2]).context("failed to read port")?;
            let port = u16::from_be_bytes([buf[0], buf[1]]);
            (addr, port)
        }
        0x03 => { // DOMAIN
            client_stream.read_exact(&mut buf[..1]).context("failed to read domain length")?;
            let len = buf[0] as usize;
            client_stream.read_exact(&mut buf[..len]).context("failed to read domain bytes")?;
            let host = String::from_utf8_lossy(&buf[..len]).to_string();
            client_stream.read_exact(&mut buf[..2]).context("failed to read port")?;
            let port = u16::from_be_bytes([buf[0], buf[1]]);
            (host, port)
        }
        0x04 => { // IPv6
            let mut v6 = [0u8; 16];
            client_stream.read_exact(&mut v6).context("failed to read IPv6 addr")?;
            let addr = std::net::Ipv6Addr::from(v6).to_string();
            client_stream.read_exact(&mut buf[..2]).context("failed to read port")?;
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
    client_stream.write_all(&success).context("failed to write SOCKS5 success reply")?;

    // Relay
    let mut server_read = channel.stream(0);
    let mut server_write = channel.stream(0);
    let mut channel_clone = channel.stream(0);
    let (mut stream_read, mut stream_write) = match client_stream.try_clone() {
        Ok(s) => (client_stream, s),
        Err(e) => return Err(e.into()),
    };

    let thread1 = thread::spawn(move || io::copy(&mut stream_read, &mut channel_clone).map(|_| ()) );
    let thread2 = thread::spawn(move || io::copy(&mut server_read, &mut stream_write).map(|_| ()) );
    let _ = thread1.join();
    let _ = thread2.join();

    if let Err(e) = server_write.flush() { warn!("flush error: {}", e); }
    if let Err(e) = channel.close() { warn!("channel close error: {}", e); }

    Ok(())
}
