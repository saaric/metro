
# (SSH) Metro
Metro is a very simple SSH tunneling tool. It connects to a remote host over SSH and forwards configured local ports to remote destinations via the SSH connection.

This repository now contains a Rust implementation at the project root. The original Go implementation was preserved under the `go/` subfolder.

## Rust version (current)

### Build
- Prerequisites: Rust toolchain (https://rustup.rs)
- Build:
  - `cargo build --release`
- Run (example):
  - `cargo run -- --host 192.168.0.100 --user sshuser --password sshuser --list tunnels.csv --port 22 --timeout 20`

### Arguments
- `--host`, `--port` — SSH server host and port (default port is 22)
- `--user`, `--password` — SSH credentials
- `--timeout` — SSH connection timeout in seconds (default 20)
- `--list` — path to a file with tunnels, each line formatted as:
  - `<local_port>;<remote_host>:<remote_port>`

Example `tunnels.csv`:
```
8080;127.0.0.1:80
5433;db.internal:5432
```

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



 