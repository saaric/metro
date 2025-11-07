
# (SSH) Metro
Metro is a very simple SSH tunneling tool. It connects to a remote host over SSH and forwards configured local ports to remote destinations via the SSH connection.

This repository now contains a Rust implementation at the project root. The original Go implementation was preserved under the `go/` subfolder.

## Rust version (current)

### Build
- Prerequisites: Rust toolchain (https://rustup.rs)
- Build:
  - `cargo build --release`
- Run (example):
  - `cargo run -- --host 192.168.0.100 --user sshuser --password sshuser --list tunnels.csv --port 22 --timeout 20 --retries 0 --retry-interval 5 --keepalive 30`

### Arguments
- `--host`, `--port` — SSH server host and port (default port is 22)
- `--user`, `--password` — SSH credentials
- `--timeout` — SSH connection timeout in seconds (default 20)
- `--retries` — max attempts to establish SSH; `0` means retry forever (default 0)
- `--retry-interval` — seconds to wait between reconnect attempts (default 5)
- `--keepalive` — send SSH keepalive every N seconds; `0` disables (default 30)
- `--list` — path to a file with tunnels. Supported line formats:
  - Static local forwarding: `<local_port>;<remote_host>:<remote_port>`
  - Dynamic forwarding (SOCKS5, like PuTTY `D<port>`):
    - `D<local_port>` (e.g. `D1080`)
    - or `<local_port>;D` (e.g. `1080;D`)

Example `tunnels.csv`:
```
# Static tunnels
8080;127.0.0.1:80
5433;db.internal:5432

# Dynamic SOCKS5 tunnel on local port 1080 (like PuTTY D1080)
D1080
# Alternatively, the same as:
# 1080;D
```

Notes:
- Dynamic mode implements SOCKS5 CONNECT (no authentication). It supports IPv4, IPv6, and domain-name targets.
- Point your applications at `127.0.0.1:<port>` as a SOCKS5 proxy.
- Dynamic mode now uses a single SSH session per dynamic listener and opens one SSH channel per client connection (multiplexing). This means only one TCP connection to the SSH server is kept while many SOCKS connections are active.
- Implementation detail: the dynamic path runs a single-threaded non-blocking event loop to avoid concurrent use of the libssh2 session. Throughput is generally good, but a single slow client can cause brief head-of-line delays. Static tunnels continue to use one SSH session per accepted connection.

Press Ctrl+C to stop the program. Logs are printed to stdout; set `RUST_LOG=info` (or `debug`) to adjust verbosity.

## Go version (legacy)
The original Go code has been moved to the `go/` directory and is left intact.

### Usage (Go)
From within the `go/` folder, build and run as before:
```
go build -o metro
./metro -host=192.168.0.100 -user=sshuser -password=sshuser -list=../tunnels.csv -port=22 -timeout=20
```

Arguments are the same as described above for the tunnels file format.



 