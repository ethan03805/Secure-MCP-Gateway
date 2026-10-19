//! Reading the Gateway's loopback metrics endpoint (CP-51, X-15) for the
//! tray (SRS FR-20.4, I-40).
//!
//! The endpoint needs no credential and carries no arguments, principals or
//! sessions, so the application learns health without holding any
//! authority. The request is a plain HTTP/1.0 GET to a loopback address
//! (the endpoint refuses anything else); the response is bounded.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

/// The values the tray needs from one exposition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Exposition {
    /// `smcp_health_state`: 0 healthy, 1 degraded, 2 fail-closed.
    pub health_state: u8,
    /// `smcp_pending_approvals`.
    pub pending_approvals: u64,
    /// `smcp_release_enforced` (FR-20.5); absent from older releases.
    pub release_enforced: Option<bool>,
    /// `smcp_emergency_stop` (FR-20.5); absent from older releases.
    pub emergency_stop: Option<bool>,
}

/// Largest exposition read (the Gateway's is a few kilobytes).
pub const MAX_BODY: usize = 1 << 20;

/// Why a read failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReadError {
    NotLoopback,
    Connect(String),
    Http(String),
    Parse(String),
}

impl std::fmt::Display for ReadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ReadError::NotLoopback => write!(f, "the metrics address is not a loopback address"),
            ReadError::Connect(e) => write!(f, "cannot reach the metrics endpoint: {e}"),
            ReadError::Http(e) => write!(f, "unexpected metrics response: {e}"),
            ReadError::Parse(e) => write!(f, "unreadable exposition: {e}"),
        }
    }
}

/// Parses the Prometheus text exposition. `smcp_health_state` is required;
/// a missing `smcp_pending_approvals` reads as 0.
pub fn parse(text: &str) -> Result<Exposition, ReadError> {
    let mut health = None;
    let mut pending = 0u64;
    let mut enforced = None;
    let mut stop = None;
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut parts = line.split_whitespace();
        let (Some(name), Some(value)) = (parts.next(), parts.next()) else {
            continue;
        };
        let num = || {
            value
                .parse::<f64>()
                .map_err(|_| ReadError::Parse(format!("{name} {value}")))
        };
        match name {
            "smcp_health_state" => {
                let v = num()?;
                if !(v == 0.0 || v == 1.0 || v == 2.0) {
                    return Err(ReadError::Parse(format!("smcp_health_state {value}")));
                }
                health = Some(v as u8);
            }
            "smcp_pending_approvals" => {
                let v = num()?;
                if !(v >= 0.0 && v.is_finite()) {
                    return Err(ReadError::Parse(format!("smcp_pending_approvals {value}")));
                }
                pending = v as u64;
            }
            "smcp_release_enforced" => enforced = Some(num()? == 1.0),
            "smcp_emergency_stop" => stop = Some(num()? == 1.0),
            _ => {}
        }
    }
    let health_state = health.ok_or_else(|| ReadError::Parse("no smcp_health_state".into()))?;
    Ok(Exposition {
        health_state,
        pending_approvals: pending,
        release_enforced: enforced,
        emergency_stop: stop,
    })
}

/// Fetches `/metrics` from a loopback address with an overall timeout.
pub fn fetch(addr: SocketAddr, timeout: Duration) -> Result<String, ReadError> {
    if !addr.ip().is_loopback() {
        return Err(ReadError::NotLoopback);
    }
    let mut s = TcpStream::connect_timeout(&addr, timeout).map_err(|e| ReadError::Connect(e.to_string()))?;
    s.set_read_timeout(Some(timeout))
        .map_err(|e| ReadError::Connect(e.to_string()))?;
    s.set_write_timeout(Some(timeout))
        .map_err(|e| ReadError::Connect(e.to_string()))?;
    // The Host header is the loopback address itself, which the endpoint
    // requires (DNS-rebinding guard in internal/metrics).
    let req =
        format!("GET /metrics HTTP/1.0\r\nHost: {addr}\r\nAccept: text/plain\r\nUser-Agent: smcp-desktop\r\n\r\n");
    s.write_all(req.as_bytes())
        .map_err(|e| ReadError::Connect(e.to_string()))?;
    let mut buf = Vec::new();
    s.take(MAX_BODY as u64 + 16 * 1024)
        .read_to_end(&mut buf)
        .map_err(|e| ReadError::Connect(e.to_string()))?;
    let text = String::from_utf8(buf).map_err(|_| ReadError::Http("not UTF-8".into()))?;
    let (head, body) = text
        .split_once("\r\n\r\n")
        .ok_or_else(|| ReadError::Http("no header end".into()))?;
    let status = head.lines().next().unwrap_or("");
    let code = status.split_whitespace().nth(1).unwrap_or("");
    if code != "200" {
        return Err(ReadError::Http(status.to_string()));
    }
    if body.len() > MAX_BODY {
        return Err(ReadError::Http("exposition too large".into()));
    }
    Ok(body.to_string())
}

/// Fetches and parses one exposition.
pub fn read(addr: SocketAddr, timeout: Duration) -> Result<Exposition, ReadError> {
    parse(&fetch(addr, timeout)?)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::claims;
    use std::net::TcpListener;
    use std::sync::{Arc, Mutex};
    use std::thread;

    pub const SAMPLE: &str =
        "# HELP smcp_health_state Gateway health\n# TYPE smcp_health_state gauge\nsmcp_health_state 1\n\
smcp_active_sessions 2\nsmcp_pending_approvals 3\nsmcp_release_enforced 0\nsmcp_emergency_stop 1\n\
smcp_calls_total{server_alias=\"t\",tool=\"t_echo\",outcome=\"delivered\",reason_code=\"\"} 4\n";

    #[test]
    fn parses_the_desktop_gauges() {
        claims::partial(&["FR-20.4"]);
        let e = parse(SAMPLE).unwrap();
        assert_eq!(
            e,
            Exposition {
                health_state: 1,
                pending_approvals: 3,
                release_enforced: Some(false),
                emergency_stop: Some(true)
            }
        );
        let old = parse("smcp_health_state 0\n").unwrap();
        assert_eq!(old.release_enforced, None);
        assert_eq!(old.emergency_stop, None);
        assert_eq!(old.pending_approvals, 0);
        assert!(parse("smcp_active_sessions 1\n").is_err());
        assert!(parse("smcp_health_state 7\n").is_err());
        assert!(parse("smcp_health_state NaN\n").is_err());
        assert!(parse("smcp_health_state 0\nsmcp_pending_approvals -1\n").is_err());
    }

    /// A one-response metrics server on a free loopback port. The response
    /// body is shared so a test can change it; `None` answers 503.
    pub struct FakeEndpoint {
        pub addr: SocketAddr,
        pub body: Arc<Mutex<Option<String>>>,
        pub hosts: Arc<Mutex<Vec<String>>>,
    }

    pub fn fake_endpoint(body: &str) -> FakeEndpoint {
        let ln = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = ln.local_addr().unwrap();
        let shared = Arc::new(Mutex::new(Some(body.to_string())));
        let hosts = Arc::new(Mutex::new(Vec::new()));
        let (b, h) = (shared.clone(), hosts.clone());
        thread::spawn(move || {
            for conn in ln.incoming() {
                let Ok(mut c) = conn else { continue };
                let mut req = [0u8; 2048];
                let n = c.read(&mut req).unwrap_or(0);
                let req = String::from_utf8_lossy(&req[..n]).to_string();
                if let Some(host) = req.lines().find_map(|l| l.strip_prefix("Host: ")) {
                    h.lock().unwrap().push(host.to_string());
                }
                let resp = match b.lock().unwrap().clone() {
                    Some(body) => format!("HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\n\r\n{body}"),
                    None => "HTTP/1.0 503 Service Unavailable\r\n\r\n".to_string(),
                };
                let _ = c.write_all(resp.as_bytes());
            }
        });
        FakeEndpoint {
            addr,
            body: shared,
            hosts,
        }
    }

    #[test]
    fn fetches_over_loopback_only() {
        claims::partial(&["FR-20.4"]);
        let ep = fake_endpoint(SAMPLE);
        let e = read(ep.addr, Duration::from_secs(2)).unwrap();
        assert_eq!(e.pending_approvals, 3);
        assert_eq!(ep.hosts.lock().unwrap().as_slice(), [ep.addr.to_string()]);
        *ep.body.lock().unwrap() = None;
        assert!(matches!(read(ep.addr, Duration::from_secs(2)), Err(ReadError::Http(_))));
        let remote: SocketAddr = "192.0.2.1:9464".parse().unwrap();
        assert_eq!(read(remote, Duration::from_millis(100)), Err(ReadError::NotLoopback));
        // Nothing listening.
        let closed = TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap();
        assert!(matches!(
            read(closed, Duration::from_millis(500)),
            Err(ReadError::Connect(_))
        ));
    }
}
