//! SR-2.8-5 on Windows: the decisions of the WebView2 certificate hook.
//!
//! WebView2 (Chromium) checks a server certificate against the Windows
//! trust store. The Gateway CA is not in it, so the admin listener's
//! certificate raises `ServerCertificateErrorDetected`; the hook
//! (`tlshook_windows`) hands the presented chain to [`on_certificate_error`],
//! which allows it only for the admin listener's host and port and only
//! when it chains to the Gateway CA ([`crate::tlspin::verify_chain`]); every
//! other certificate error is cancelled. A certificate that Windows does
//! trust raises no error, so every committed https page of the console
//! window is checked as well: the hook enables the DevTools protocol's
//! Security domain, whose `Security.visibleSecurityStateChanged` event
//! carries the certificate chain the page was loaded with, and
//! [`on_committed`] refuses the page unless that chain leads to the
//! Gateway CA, as WebKitGTK's committed-load check does on Linux. A page
//! for which no such event arrives within [`CHECK_DEADLINE`] is refused
//! too ([`Watch`]). The Windows trust store therefore never decides alone.
//! (`Network.getCertificate` was the first choice; current Chromium
//! answers it with an empty list.)
//!
//! This module is plain logic, built and tested on every platform; the
//! COM calls are in `tlshook_windows`.

use std::time::Duration;

use rustls_pki_types::CertificateDer;

use crate::tlspin::{self, PinError};

/// The listener the console window may trust, and its anchors.
#[derive(Clone, Debug)]
pub struct Pin {
    pub host: String,
    pub port: u16,
    pub anchors: Result<Vec<CertificateDer<'static>>, PinError>,
}

/// What the certificate error handler answers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// The chain leads to the Gateway CA and names the host: allow this
    /// certificate for this host (WebView2's ALWAYS_ALLOW, kept for the
    /// session of the window's non-persistent profile).
    Allow,
    /// Refuse the request, with the reason shown in the window title.
    Cancel(String),
}

/// The host and port of an http(s) URL, the IPv6 host without brackets.
pub fn host_port(uri: &str) -> Option<(String, u16)> {
    let u = url::Url::parse(uri).ok()?;
    let host = match u.host()? {
        url::Host::Domain(d) => d.to_string(),
        url::Host::Ipv4(ip) => ip.to_string(),
        url::Host::Ipv6(ip) => ip.to_string(),
    };
    Some((host, u.port_or_known_default()?))
}

fn is_admin(pin: &Pin, uri: &str) -> bool {
    url::Url::parse(uri).is_ok_and(|u| u.scheme() == "https")
        && host_port(uri).is_some_and(|(h, p)| h.eq_ignore_ascii_case(&pin.host) && p == pin.port)
}

fn verify(pin: &Pin, chain: &[Vec<u8>], now: u64) -> Result<(), String> {
    let anchors = pin.anchors.as_ref().map_err(|e| e.to_string())?;
    tlspin::verify_chain(chain, anchors, &pin.host, now).map_err(|e| e.to_string())
}

/// The presented chain as WebView2 reports it: the server certificate's
/// PEM (`ICoreWebView2Certificate::ToPemEncoding`) and the issuers' PEM
/// (`PemEncodedIssuerCertificateChain`), leaf first.
pub fn chain_from_pem(leaf: &str, issuers: &[String]) -> Result<Vec<Vec<u8>>, String> {
    let mut chain = tlspin::parse_pem_chain(leaf.as_bytes()).map_err(|e| e.to_string())?;
    if chain.len() != 1 {
        return Err("the server certificate is not one PEM certificate".into());
    }
    for i in issuers {
        chain.extend(tlspin::parse_pem_chain(i.as_bytes()).map_err(|e| e.to_string())?);
    }
    Ok(chain)
}

/// `ServerCertificateErrorDetected`: allow only the admin listener with a
/// certificate that chains to the Gateway CA.
pub fn on_certificate_error(pin: &Pin, request_uri: &str, chain: Result<Vec<Vec<u8>>, String>, now: u64) -> Verdict {
    if !is_admin(pin, request_uri) {
        return Verdict::Cancel("the console window loads only the admin listener".into());
    }
    match chain.and_then(|c| verify(pin, &c, now)) {
        Ok(()) => Verdict::Allow,
        Err(e) => Verdict::Cancel(e),
    }
}

/// How long a committed https page may wait for its security state
/// before it is refused.
pub const CHECK_DEADLINE: Duration = Duration::from_secs(10);

/// The DevTools event that carries the page's certificate.
pub const SECURITY_EVENT: &str = "Security.visibleSecurityStateChanged";

/// Whether a committed page needs the certificate check: every https page.
/// The blank start page and the bundled error page
/// (`http://tauri.localhost`) carry no certificate.
pub fn needs_check(page: &str) -> bool {
    url::Url::parse(page)
        .map(|u| u.scheme() != "http" && u.scheme() != "about")
        .unwrap_or(true)
}

/// The DER chain in a `Security.visibleSecurityStateChanged` event
/// (`visibleSecurityState.certificateSecurityState.certificate`, base64
/// DER, leaf first).
pub fn chain_from_security_state(json: &str) -> Result<Vec<Vec<u8>>, String> {
    let v: serde_json::Value =
        serde_json::from_str(json).map_err(|e| format!("the security state is not JSON: {e}"))?;
    let certs = v
        .pointer("/visibleSecurityState/certificateSecurityState/certificate")
        .and_then(|t| t.as_array())
        .ok_or("the admin listener presented no certificate")?;
    let mut chain = Vec::new();
    for c in certs {
        let b64 = c
            .as_str()
            .ok_or("the security state has a certificate that is not text")?;
        if b64.is_empty()
            || !b64
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'+' | b'/' | b'='))
        {
            return Err("the security state has a certificate that is not base64".into());
        }
        let mut pem = String::from("-----BEGIN CERTIFICATE-----\n");
        for line in b64.as_bytes().chunks(64) {
            pem.push_str(std::str::from_utf8(line).unwrap_or_default());
            pem.push('\n');
        }
        pem.push_str("-----END CERTIFICATE-----\n");
        chain.extend(tlspin::parse_pem_chain(pem.as_bytes()).map_err(|e| e.to_string())?);
    }
    if chain.is_empty() {
        return Err("the admin listener presented no certificate".into());
    }
    Ok(chain)
}

/// The committed-load check: a committed https page is kept only when it
/// is on the admin origin and the certificate of its security state chains
/// to the Gateway CA. `state` is the event's JSON, or why it could not be
/// read (which refuses).
pub fn on_committed(pin: &Pin, page: &str, state: Result<&str, String>, now: u64) -> Result<(), String> {
    if !needs_check(page) {
        return Ok(());
    }
    if !is_admin(pin, page) {
        return Err("the console window loads only the admin listener".into());
    }
    let chain = state.and_then(chain_from_security_state)?;
    verify(pin, &chain, now)
}

/// Which committed page still waits for its check. Each committed https
/// page starts a new round; a passed check settles the current round; a
/// round that is still open at its deadline is refused.
#[derive(Debug, Default)]
pub struct Watch {
    round: u64,
    settled: bool,
}

impl Watch {
    /// A page was committed; returns its round.
    pub fn begin(&mut self) -> u64 {
        self.round += 1;
        self.settled = false;
        self.round
    }

    /// The current page passed the check.
    pub fn settle(&mut self) {
        self.settled = true;
    }

    /// Whether `round` is still the current page and unchecked.
    pub fn overdue(&self, round: u64) -> bool {
        self.round == round && !self.settled
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::claims;
    use rcgen::{BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair, SanType};

    struct Ca {
        issuer: Issuer<'static, KeyPair>,
        pem: String,
    }

    fn ca(name: &str) -> Ca {
        let mut p = CertificateParams::new(Vec::<String>::new()).unwrap();
        p.distinguished_name.push(DnType::CommonName, name);
        p.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let key = KeyPair::generate().unwrap();
        let cert = p.self_signed(&key).unwrap();
        Ca {
            pem: cert.pem(),
            issuer: Issuer::new(p, key),
        }
    }

    /// A server certificate for 127.0.0.1 and localhost, as PEM and DER.
    fn leaf(ca: &Ca) -> (String, Vec<u8>) {
        let mut p = CertificateParams::new(Vec::<String>::new()).unwrap();
        p.subject_alt_names = vec![
            SanType::IpAddress("127.0.0.1".parse().unwrap()),
            SanType::DnsName("localhost".try_into().unwrap()),
        ];
        p.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        p.not_before = rcgen::date_time_ymd(2026, 1, 1);
        p.not_after = rcgen::date_time_ymd(2027, 1, 1);
        let key = KeyPair::generate().unwrap();
        let c = p.signed_by(&key, &ca.issuer).unwrap();
        (c.pem(), c.der().to_vec())
    }

    // 2026-10-18T00:00:00Z
    const NOW: u64 = 1_792_281_600;

    fn pin(gw: &Ca) -> Pin {
        Pin {
            host: "127.0.0.1".into(),
            port: 8444,
            anchors: tlspin::parse_ca_bundle(gw.pem.as_bytes()),
        }
    }

    fn b64(der: &[u8]) -> String {
        const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut s = String::new();
        for c in der.chunks(3) {
            let n = (u32::from(c[0]) << 16)
                | (u32::from(*c.get(1).unwrap_or(&0)) << 8)
                | u32::from(*c.get(2).unwrap_or(&0));
            for i in 0..4 {
                if i <= c.len() {
                    s.push(A[((n >> (18 - 6 * i)) & 63) as usize] as char);
                } else {
                    s.push('=');
                }
            }
        }
        s
    }

    #[test]
    fn the_error_handler_allows_only_the_gateway_ca_at_the_admin_listener() {
        claims::partial(&["SR-2.8-5", "FR-20.1"]);
        let gw = ca("Gateway CA");
        let p = pin(&gw);
        let (good, _) = leaf(&gw);
        let url = "https://127.0.0.1:8444/approvals";
        assert_eq!(
            on_certificate_error(&p, url, chain_from_pem(&good, &[]), NOW),
            Verdict::Allow
        );
        // The issuer chain WebView2 reports may include the CA itself.
        assert_eq!(
            on_certificate_error(&p, url, chain_from_pem(&good, std::slice::from_ref(&gw.pem)), NOW),
            Verdict::Allow
        );

        // A different CA, for example one Windows trusts.
        let other = ca("Some other CA");
        let (foreign, _) = leaf(&other);
        assert!(matches!(
            on_certificate_error(&p, url, chain_from_pem(&foreign, std::slice::from_ref(&other.pem)), NOW),
            Verdict::Cancel(e) if e.contains("does not chain to the Gateway CA")
        ));
        // Expired at the time of the check.
        assert!(matches!(
            on_certificate_error(&p, url, chain_from_pem(&good, &[]), 1_900_000_000),
            Verdict::Cancel(_)
        ));
        // Another host or port, even with the Gateway CA.
        for u in [
            "https://localhost:8444/",
            "https://127.0.0.1:8445/",
            "https://example.com/",
            "http://127.0.0.1:8444/",
        ] {
            assert!(
                matches!(
                    on_certificate_error(&p, u, chain_from_pem(&good, &[]), NOW),
                    Verdict::Cancel(_)
                ),
                "{u}"
            );
        }
        // An unusable CA bundle trusts nothing.
        let broken = Pin {
            anchors: tlspin::parse_ca_bundle(b""),
            ..p.clone()
        };
        assert!(matches!(
            on_certificate_error(&broken, url, chain_from_pem(&good, &[]), NOW),
            Verdict::Cancel(_)
        ));
        // A garbled certificate.
        assert!(matches!(
            on_certificate_error(&p, url, chain_from_pem("not pem", &[]), NOW),
            Verdict::Cancel(_)
        ));
        assert!(chain_from_pem(&format!("{good}{good}"), &[]).is_err());
    }

    fn state(certs: &[&[u8]]) -> String {
        let list: Vec<String> = certs.iter().map(|c| format!("\"{}\"", b64(c))).collect();
        format!(
            r#"{{"visibleSecurityState":{{"securityState":"secure","securityStateIssueIds":[],"certificateSecurityState":{{"protocol":"TLS 1.3","certificate":[{}],"issuer":"x"}}}}}}"#,
            list.join(",")
        )
    }

    #[test]
    fn the_committed_check_refuses_a_certificate_windows_trusts_but_the_gateway_does_not() {
        claims::partial(&["SR-2.8-5", "FR-20.1"]);
        let gw = ca("Gateway CA");
        let p = pin(&gw);
        let (_, good) = leaf(&gw);
        let other = ca("Windows-trusted CA");
        let (_, foreign) = leaf(&other);
        let page = "https://127.0.0.1:8444/";
        let ok = state(&[&good]);
        assert_eq!(on_committed(&p, page, Ok(&ok), NOW), Ok(()));
        let bad = state(&[&foreign]);
        assert!(on_committed(&p, page, Ok(&bad), NOW)
            .unwrap_err()
            .contains("does not chain to the Gateway CA"));
        // Fail closed when the chain cannot be read.
        for answer in [
            Err("Security.enable failed".to_string()),
            Ok("{}".to_string()),
            Ok(r#"{"visibleSecurityState":{"securityState":"insecure","securityStateIssueIds":["scheme-is-not-cryptographic"]}}"#.to_string()),
            Ok(state(&[])),
            Ok(state(&[]).replace("[]", r#"["***"]"#)),
            Ok("not json".to_string()),
        ] {
            assert!(
                on_committed(&p, page, answer.as_deref().map_err(Clone::clone), NOW).is_err(),
                "{answer:?}"
            );
        }
        // Pages without a certificate are not checked; other https pages are refused.
        assert_eq!(on_committed(&p, "about:blank", Err("x".into()), NOW), Ok(()));
        assert_eq!(
            on_committed(&p, "http://tauri.localhost/error.html", Err("x".into()), NOW),
            Ok(())
        );
        assert!(on_committed(&p, "https://example.com/", Ok(&ok), NOW).is_err());
        assert!(needs_check("https://127.0.0.1:8444/"));
        assert!(needs_check("not a url"));
    }

    #[test]
    fn a_page_without_a_checked_certificate_is_refused_at_the_deadline() {
        claims::partial(&["SR-2.8-5"]);
        let mut w = Watch::default();
        let first = w.begin();
        assert!(w.overdue(first));
        w.settle();
        assert!(!w.overdue(first));
        // A new page opens a new round; the old round's deadline no longer counts.
        let second = w.begin();
        assert!(!w.overdue(first));
        assert!(w.overdue(second));
        assert!(CHECK_DEADLINE <= Duration::from_secs(15));
        assert_eq!(SECURITY_EVENT, "Security.visibleSecurityStateChanged");
    }

    #[test]
    fn ipv6_admin_listeners_match_by_host_and_port() {
        claims::partial(&["SR-2.8-5"]);
        assert_eq!(host_port("https://[::1]:8444/x"), Some(("::1".into(), 8444)));
        let gw = ca("Gateway CA");
        let p = Pin {
            host: "::1".into(),
            ..pin(&gw)
        };
        assert!(is_admin(&p, "https://[::1]:8444/approvals"));
        assert!(!is_admin(&p, "https://127.0.0.1:8444/"));
    }
}
