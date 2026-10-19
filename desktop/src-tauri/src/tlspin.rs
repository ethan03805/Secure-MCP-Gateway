//! Certificate check for the console window (SRS SR-2.8-5).
//!
//! The console window accepts the admin listener only when its certificate
//! chains to the installation's Gateway server CA (the bundle `tls/ca.crt`
//! of the state directory, which holds the active CA and, during a
//! rotation, the next one) and names the configured host. The operating
//! system's trust store plays no part: a certificate the system trusts but
//! that does not chain to the Gateway CA is refused like any other. The
//! platform hooks (`tlshook_macos`, `tlshook_linux`) hand the presented
//! chain to [`verify_chain`].

use std::fmt;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, ServerName, TrustAnchor, UnixTime};
use webpki::{EndEntityCert, KeyUsage};

/// Why a certificate chain was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PinError {
    /// The CA bundle could not be read or holds no certificate.
    NoAnchors(String),
    /// The listener presented no certificate.
    EmptyChain,
    /// The chain does not lead to the Gateway CA, is expired or not yet
    /// valid, or is not a server certificate.
    Untrusted(String),
    /// The certificate does not name the configured host.
    WrongName(String),
}

impl fmt::Display for PinError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PinError::NoAnchors(e) => write!(f, "the Gateway CA bundle is unusable: {e}"),
            PinError::EmptyChain => write!(f, "the admin listener presented no certificate"),
            PinError::Untrusted(e) => write!(f, "the certificate does not chain to the Gateway CA: {e}"),
            PinError::WrongName(e) => write!(f, "the certificate does not name the configured host: {e}"),
        }
    }
}

/// Parses a PEM bundle of CA certificates (the Gateway's `tls/ca.crt`).
pub fn parse_ca_bundle(pem: &[u8]) -> Result<Vec<CertificateDer<'static>>, PinError> {
    let mut out = Vec::new();
    for c in CertificateDer::pem_slice_iter(pem) {
        out.push(c.map_err(|e| PinError::NoAnchors(e.to_string()))?);
    }
    if out.is_empty() {
        return Err(PinError::NoAnchors("no CERTIFICATE block".into()));
    }
    Ok(out)
}

/// Parses a PEM chain as WebKitGTK reports it (leaf first).
pub fn parse_pem_chain(pem: &[u8]) -> Result<Vec<Vec<u8>>, PinError> {
    let mut out = Vec::new();
    for c in CertificateDer::pem_slice_iter(pem) {
        out.push(c.map_err(|e| PinError::Untrusted(e.to_string()))?.to_vec());
    }
    Ok(out)
}

/// Seconds since the Unix epoch now.
pub fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Verifies a presented chain (leaf first, DER) against the Gateway CA
/// bundle as the only trust anchors, for TLS server use, at `now_unix`,
/// and checks that the leaf names `host` (a DNS name or an IP address).
pub fn verify_chain(chain: &[Vec<u8>], ca: &[CertificateDer<'_>], host: &str, now_unix: u64) -> Result<(), PinError> {
    let leaf_der = chain.first().ok_or(PinError::EmptyChain)?;
    let anchors: Vec<TrustAnchor<'_>> = ca
        .iter()
        .map(|c| webpki::anchor_from_trusted_cert(c).map_err(|e| PinError::NoAnchors(format!("{e:?}"))))
        .collect::<Result<_, _>>()?;
    if anchors.is_empty() {
        return Err(PinError::NoAnchors("no CA certificate".into()));
    }
    let leaf_cert = CertificateDer::from(leaf_der.as_slice());
    let leaf = EndEntityCert::try_from(&leaf_cert).map_err(|e| PinError::Untrusted(format!("{e:?}")))?;
    let intermediates: Vec<CertificateDer<'_>> =
        chain[1..].iter().map(|c| CertificateDer::from(c.as_slice())).collect();
    leaf.verify_for_usage(
        webpki::ALL_VERIFICATION_ALGS,
        &anchors,
        &intermediates,
        UnixTime::since_unix_epoch(Duration::from_secs(now_unix)),
        KeyUsage::server_auth(),
        None,
        None,
    )
    .map_err(|e| PinError::Untrusted(format!("{e:?}")))?;
    let name = ServerName::try_from(host).map_err(|e| PinError::WrongName(format!("{host}: {e}")))?;
    leaf.verify_is_valid_for_subject_name(&name)
        .map_err(|e| PinError::WrongName(format!("{host}: {e:?}")))?;
    Ok(())
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

    fn leaf(ca: &Ca, sans: Vec<SanType>, not_after: (i32, u8, u8)) -> Vec<u8> {
        let mut p = CertificateParams::new(Vec::<String>::new()).unwrap();
        p.subject_alt_names = sans;
        p.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        p.not_before = rcgen::date_time_ymd(2026, 1, 1);
        p.not_after = rcgen::date_time_ymd(not_after.0, not_after.1, not_after.2);
        let key = KeyPair::generate().unwrap();
        p.signed_by(&key, &ca.issuer).unwrap().der().to_vec()
    }

    fn loopback() -> Vec<SanType> {
        vec![
            SanType::IpAddress("127.0.0.1".parse().unwrap()),
            SanType::DnsName("localhost".try_into().unwrap()),
        ]
    }

    // 2026-10-18T00:00:00Z
    const NOW: u64 = 1_792_281_600;

    #[test]
    fn accepts_only_the_gateway_ca_and_the_configured_name() {
        claims::partial(&["SR-2.8-5"]);
        let gw = ca("Gateway CA");
        let anchors = parse_ca_bundle(gw.pem.as_bytes()).unwrap();
        let good = leaf(&gw, loopback(), (2027, 1, 1));
        assert_eq!(
            verify_chain(std::slice::from_ref(&good), &anchors, "127.0.0.1", NOW),
            Ok(())
        );
        assert_eq!(
            verify_chain(std::slice::from_ref(&good), &anchors, "localhost", NOW),
            Ok(())
        );

        // Another CA (for example one the operating system trusts).
        let other = ca("Some other CA");
        let foreign = leaf(&other, loopback(), (2027, 1, 1));
        assert!(matches!(
            verify_chain(&[foreign], &anchors, "127.0.0.1", NOW),
            Err(PinError::Untrusted(_))
        ));

        // Expired, and not yet valid.
        let expired = leaf(&gw, loopback(), (2026, 6, 1));
        assert!(matches!(
            verify_chain(&[expired], &anchors, "127.0.0.1", NOW),
            Err(PinError::Untrusted(_))
        ));
        assert!(matches!(
            verify_chain(std::slice::from_ref(&good), &anchors, "127.0.0.1", 1_700_000_000),
            Err(PinError::Untrusted(_))
        ));

        // Another name.
        let other_name = leaf(
            &gw,
            vec![SanType::IpAddress("127.0.0.2".parse().unwrap())],
            (2027, 1, 1),
        );
        assert!(matches!(
            verify_chain(&[other_name], &anchors, "127.0.0.1", NOW),
            Err(PinError::WrongName(_))
        ));
        assert!(matches!(
            verify_chain(&[good], &anchors, "gateway.example", NOW),
            Err(PinError::WrongName(_))
        ));

        // Nothing presented.
        assert_eq!(verify_chain(&[], &anchors, "127.0.0.1", NOW), Err(PinError::EmptyChain));
    }

    #[test]
    fn a_rotation_bundle_trusts_both_cas() {
        claims::partial(&["SR-2.8-5"]);
        let active = ca("Gateway CA 1");
        let next = ca("Gateway CA 2");
        let bundle = format!("{}{}", active.pem, next.pem);
        let anchors = parse_ca_bundle(bundle.as_bytes()).unwrap();
        assert_eq!(anchors.len(), 2);
        for c in [&active, &next] {
            assert_eq!(
                verify_chain(&[leaf(c, loopback(), (2027, 1, 1))], &anchors, "127.0.0.1", NOW),
                Ok(())
            );
        }
    }

    #[test]
    fn an_empty_or_garbled_bundle_trusts_nothing() {
        claims::partial(&["SR-2.8-5"]);
        assert!(matches!(parse_ca_bundle(b""), Err(PinError::NoAnchors(_))));
        assert!(matches!(
            parse_ca_bundle(b"not a certificate"),
            Err(PinError::NoAnchors(_))
        ));
        assert!(verify_chain(&[vec![1, 2, 3]], &[], "127.0.0.1", NOW).is_err());
    }

    /// A CA and server certificate made by the Gateway's own key code
    /// (`keys.Ensure`, Go), committed as public test data: the check must
    /// accept what smcpd actually serves, including the CA's name
    /// constraints.
    #[test]
    fn accepts_a_certificate_made_by_smcpd() {
        claims::partial(&["SR-2.8-5"]);
        let ca_pem = include_bytes!("../tests/fixtures/gateway-ca.crt");
        let server_pem = include_bytes!("../tests/fixtures/gateway-server.crt");
        // Inside the fixture server certificate's validity (2026-10-19 to 2027-01-17).
        const FIXTURE_NOW: u64 = 1_793_491_200; // 2026-11-01T00:00:00Z
        let anchors = parse_ca_bundle(ca_pem).unwrap();
        let chain = parse_pem_chain(server_pem).unwrap();
        assert_eq!(verify_chain(&chain, &anchors, "127.0.0.1", FIXTURE_NOW), Ok(()));
        assert_eq!(verify_chain(&chain, &anchors, "localhost", FIXTURE_NOW), Ok(()));
        assert!(matches!(
            verify_chain(&chain, &anchors, "192.0.2.1", FIXTURE_NOW),
            Err(PinError::WrongName(_))
        ));
        let other = ca("Some other CA");
        let foreign = parse_ca_bundle(other.pem.as_bytes()).unwrap();
        assert!(matches!(
            verify_chain(&chain, &foreign, "127.0.0.1", FIXTURE_NOW),
            Err(PinError::Untrusted(_))
        ));
    }
}
