use super::*;
use tempfile::NamedTempFile;
use std::io::Write as IoWrite;

#[test]
fn test_parse_host_port_basic() {
    let (h, p) = parse_host_port("127.0.0.1:80").unwrap();
    assert_eq!(h, "127.0.0.1");
    assert_eq!(p, 80);

    let (h2, p2) = parse_host_port("db.internal:5432").unwrap();
    assert_eq!(h2, "db.internal");
    assert_eq!(p2, 5432);
}

#[test]
fn test_parse_host_port_ipv6_variants() {
    // IPv6 without brackets, split on last ':'
    let (h, p) = parse_host_port("::1:443").unwrap();
    assert_eq!(h, "::1");
    assert_eq!(p, 443);

    // With brackets
    let (h2, p2) = parse_host_port("[2001:db8::1]:8443").unwrap();
    assert_eq!(h2, "[2001:db8::1]");
    assert_eq!(p2, 8443);
}

#[test]
fn test_parse_host_port_errors() {
    assert!(parse_host_port("").is_err());
    assert!(parse_host_port("noport").is_err());
    assert!(parse_host_port("host:abc").is_err());
    // Current implementation allows empty host with trailing port, e.g., ":80"
    let (h, p) = parse_host_port(":80").unwrap();
    assert_eq!(h, "");
    assert_eq!(p, 80);
}

fn write_temp_tunnels(content: &str) -> NamedTempFile {
    let mut f = NamedTempFile::new().unwrap();
    f.write_all(content.as_bytes()).unwrap();
    f.flush().unwrap();
    f
}

#[test]
fn test_read_tunnels_static_and_dynamic() {
    let content = r#"
# comment

8080;127.0.0.1:80
5433;db.internal:5432
D1080
1081;D
"#;
    let f = write_temp_tunnels(content);
    let list_path = f.path().to_path_buf();
    let tunnels = read_tunnels(&list_path).unwrap();

    // We expect 4 valid entries: 2 static + 2 dynamic
    assert_eq!(tunnels.len(), 4, "parsed tunnels: {:?}", tunnels);

    // Verify presence of each expected tunnel
    let mut have_static1 = false;
    let mut have_static2 = false;
    let mut have_dyn1 = false;
    let mut have_dyn2 = false;
    for t in tunnels {
        match t.kind {
            TunnelKind::Static { ref remote_host, remote_port } => {
                if t.local_port == 8080 && remote_host == "127.0.0.1" && remote_port == 80 {
                    have_static1 = true;
                }
                if t.local_port == 5433 && remote_host == "db.internal" && remote_port == 5432 {
                    have_static2 = true;
                }
            }
            TunnelKind::Dynamic => {
                if t.local_port == 1080 { have_dyn1 = true; }
                if t.local_port == 1081 { have_dyn2 = true; }
            }
        }
    }
    assert!(have_static1 && have_static2 && have_dyn1 && have_dyn2);
}

#[test]
fn test_read_tunnels_invalid_line_errors() {
    // Invalid static destination should produce an error
    let content = "9090;missingport\n";
    let f = write_temp_tunnels(content);
    let list_path = f.path().to_path_buf();
    let res = read_tunnels(&list_path);
    assert!(res.is_err(), "expected error on invalid line, got: {:?}", res);
}
