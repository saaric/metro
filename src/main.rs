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

    /// CSV list of tunnels (<local_port>;<remote_host>:<remote_port>)
    #[arg(long, value_name = "FILE")]
    list: PathBuf,
}

#[derive(Debug, Clone)]
struct TunnelCfg {
    local_port: u16,
    remote_host: String,
    remote_port: u16,
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
                error!("Tunnel {} -> {}:{} failed: {:#}", t.local_port, t.remote_host, t.remote_port, e);
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
        let parts: Vec<&str> = line.split(';').collect();
        if parts.len() != 2 {
            warn!("Skipping invalid tunnel line: {}", line);
            continue;
        }
        let local_port: u16 = parts[0].parse().with_context(|| format!("invalid local port in line: {}", line))?;
        let dst = parts[1];
        let (host, port) = parse_host_port(dst).with_context(|| format!("invalid remote host:port in line: {}", line))?;
        res.push(TunnelCfg { local_port, remote_host: host.to_string(), remote_port: port });
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
    info!("Listening on {} and forwarding via SSH {}:{} to {}:{}", bind_addr, args.host, args.port, t.remote_host, t.remote_port);
    listener.set_nonblocking(true).ok();

    while !shutdown.load(Ordering::SeqCst) {
        match listener.accept() {
            Ok((client_stream, addr)) => {
                info!("Incoming connection from {} to {}", addr, bind_addr);
                let a = args.clone();
                let tc = t.clone();
                let s = shutdown.clone();
                thread::spawn(move || {
                    if let Err(e) = handle_connection(&a, &tc, client_stream, s) {
                        error!("Connection handling error: {:#}", e);
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

fn handle_connection(args: &Args, t: &TunnelCfg, mut client_stream: TcpStream, shutdown: Arc<AtomicBool>) -> Result<()> {
    client_stream.set_nodelay(true).ok();

    // Establish TCP to SSH server
    let ssh_addr = format!("{}:{}", args.host, args.port);
    let mut tcp = TcpStream::connect(&ssh_addr)
        .with_context(|| format!("failed to connect to SSH server at {}", ssh_addr))?;
    tcp.set_read_timeout(Some(Duration::from_secs(args.timeout))).ok();
    tcp.set_write_timeout(Some(Duration::from_secs(args.timeout))).ok();

    // SSH handshake
    let mut sess = Session::new().context("failed to create SSH session")?;
    sess.set_tcp_stream(tcp);
    sess.set_timeout((args.timeout * 1000) as u32);
    sess.handshake().context("SSH handshake failed")?;
    sess.userauth_password(&args.user, &args.password)
        .context("SSH authentication failed")?;
    if !sess.authenticated() {
        anyhow::bail!("SSH authentication rejected");
    }

    // Open direct-tcpip channel to target
    let mut channel = sess
        .channel_direct_tcpip(&t.remote_host, t.remote_port, None)
        .with_context(|| format!("failed to open direct-tcpip channel to {}:{}", t.remote_host, t.remote_port))?;

    // Bi-directional relay
    let mut server_read = channel.stream(0);
    let mut server_write = channel.stream(0);

    // client -> server
    let mut ch_clone = channel.stream(0);
    let (mut cr, mut cw) = match client_stream.try_clone() {
        Ok(s) => (client_stream, s),
        Err(e) => return Err(e.into()),
    };

    let t1 = thread::spawn(move || io::copy(&mut cr, &mut ch_clone).map(|_| ()) );
    let t2 = thread::spawn(move || io::copy(&mut server_read, &mut cw).map(|_| ()) );

    let _ = t1.join();
    let _ = t2.join();

    // Attempt to close channel gracefully
    if let Err(e) = server_write.flush() { warn!("flush error: {}", e); }
    if let Err(e) = channel.close() { warn!("channel close error: {}", e); }

    Ok(())
}
