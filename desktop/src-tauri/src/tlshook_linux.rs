//! SR-2.8-5 on Linux: WebKitGTK certificate handling.
//!
//! WebKitGTK refuses a certificate the system does not trust and emits
//! `load-failed-with-tls-errors`. For the admin listener's host and port
//! the handler verifies the presented chain with
//! [`crate::tlspin::verify_chain`]; on success it allows that one
//! certificate for that host in the window's web context and reloads, and
//! otherwise shows the bundled error page. Because a certificate the
//! system does trust raises no error, every committed load is also checked
//! against the Gateway CA through the page's TLS information, so the
//! system trust store never decides alone.

use gio::prelude::TlsCertificateExt;
use rustls_pki_types::CertificateDer;
use webkit2gtk::{gio, LoadEvent, WebContextExt, WebViewExt};

use crate::tlspin;

#[derive(Clone)]
pub struct Pin {
    pub host: String,
    pub port: u16,
    pub anchors: Result<Vec<CertificateDer<'static>>, tlspin::PinError>,
}

fn chain_of(cert: &gio::TlsCertificate) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let mut cur = Some(cert.clone());
    while let Some(c) = cur {
        if let Some(pem) = c.certificate_pem() {
            if let Ok(mut ders) = tlspin::parse_pem_chain(pem.as_bytes()) {
                out.append(&mut ders);
            }
        }
        cur = c.issuer();
        if out.len() > 8 {
            break;
        }
    }
    out
}

fn host_port(uri: &str) -> Option<(String, u16)> {
    let u = url::Url::parse(uri).ok()?;
    let host = match u.host()? {
        url::Host::Domain(d) => d.to_string(),
        url::Host::Ipv4(ip) => ip.to_string(),
        url::Host::Ipv6(ip) => ip.to_string(),
    };
    Some((host, u.port_or_known_default()?))
}

fn check(pin: &Pin, cert: &gio::TlsCertificate) -> Result<(), String> {
    let anchors = pin.anchors.as_ref().map_err(|e| e.to_string())?;
    tlspin::verify_chain(&chain_of(cert), anchors, &pin.host, tlspin::now_unix()).map_err(|e| e.to_string())
}

/// Connects the handlers. `refused` shows the error page.
pub fn install(wv: &webkit2gtk::WebView, pin: Pin, refused: impl Fn(String) + Clone + 'static) {
    let (p1, r1) = (pin.clone(), refused.clone());
    wv.connect_load_failed_with_tls_errors(move |wv, uri, cert, _flags| {
        let ours = host_port(uri).is_some_and(|(h, port)| h.eq_ignore_ascii_case(&p1.host) && port == p1.port);
        if !ours {
            r1("the console window loads only the admin listener".into());
            return true;
        }
        match check(&p1, cert) {
            Ok(()) => {
                if let Some(ctx) = wv.context() {
                    ctx.allow_tls_certificate_for_host(cert, &p1.host);
                    wv.load_uri(uri);
                }
            }
            Err(e) => r1(e),
        }
        true
    });
    wv.connect_load_changed(move |wv, ev| {
        if ev != LoadEvent::Committed {
            return;
        }
        let Some(uri) = wv.uri() else { return };
        if !uri.starts_with("https:") {
            return;
        }
        let ok = match wv.tls_info() {
            Some((cert, _)) => check(&pin, &cert),
            None => Err("no TLS information for the page".into()),
        };
        if let Err(e) = ok {
            wv.stop_loading();
            refused(e);
        }
    });
}
