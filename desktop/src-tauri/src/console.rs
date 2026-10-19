//! The console in a native window (SRS FR-20.6, SR-2-4, SR-2-5, SR-2-6,
//! SR-2.8-5, SR-2.9-4, F-102, I-41).
//!
//! The window loads the console that `smcpd` serves on the admin listener,
//! never a bundled copy, so the console's own sign-in, CSRF protection,
//! role matrix and Content Security Policy apply unchanged. The window:
//!
//! - is named [`CONSOLE_LABEL`], which no capability file lists, so it has
//!   no Tauri permission and no application command (SR-2-5);
//! - uses a non-persistent (incognito) web data store, so the session
//!   cookie never reaches disk (SR-2-4);
//! - navigates only within the admin listener's origin; a link to another
//!   origin opens in the default browser, and every other scheme is
//!   refused (SR-2-6, FR-20.6);
//! - accepts the listener only with a certificate that chains to the
//!   Gateway CA (`tlspin`, platform hooks), and shows a bundled error page
//!   with no way to proceed otherwise (SR-2.8-5).

use url::Url;

use crate::settings::AdminOrigin;

/// The console window's label. No capability names it.
pub const CONSOLE_LABEL: &str = "console";

/// The window's fixed configuration, kept as data so tests can check it.
#[derive(Debug, Clone, PartialEq)]
pub struct WindowConfig {
    pub label: &'static str,
    pub title: &'static str,
    /// Non-persistent web data store (SR-2-4).
    pub incognito: bool,
    /// Developer tools stay off.
    pub devtools: bool,
    pub width: f64,
    pub height: f64,
}

pub const WINDOW: WindowConfig = WindowConfig {
    label: CONSOLE_LABEL,
    title: "Secure MCP Gateway Console",
    incognito: true,
    devtools: false,
    width: 1280.0,
    height: 860.0,
};

/// A console page the application may open: from the menu, a
/// notification, or an accepted deep link (FR-20.28, `deeplink`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Page {
    Home,
    /// The Approvals view, G-13.
    Approvals,
    /// One approval in the Approvals view.
    Approval(ApprovalId),
}

/// An approval ID that is a UUID in its canonical 36-character form, kept
/// as lower-case text. Only [`ApprovalId::parse`] makes one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ApprovalId([u8; 36]);

impl ApprovalId {
    pub fn parse(s: &str) -> Option<ApprovalId> {
        let b = s.as_bytes();
        if b.len() != 36 {
            return None;
        }
        let mut out = [0u8; 36];
        for (i, &c) in b.iter().enumerate() {
            let dash = matches!(i, 8 | 13 | 18 | 23);
            out[i] = match (dash, c) {
                (true, b'-') => b'-',
                (false, b'0'..=b'9' | b'a'..=b'f') => c,
                (false, b'A'..=b'F') => c.to_ascii_lowercase(),
                _ => return None,
            };
        }
        Some(ApprovalId(out))
    }

    pub fn as_str(&self) -> &str {
        // Only ASCII hex digits and hyphens are stored.
        std::str::from_utf8(&self.0).unwrap_or("")
    }
}

impl Page {
    pub fn path(self) -> String {
        match self {
            Page::Home => "/".into(),
            Page::Approvals => "/approvals".into(),
            Page::Approval(id) => format!("/approvals/{}", id.as_str()),
        }
    }
}

/// The bundled error page for a refused certificate (or an unusable CA
/// bundle). It is static: no script, no link to proceed.
pub fn error_page() -> Url {
    #[cfg(windows)]
    let s = "http://tauri.localhost/error.html";
    #[cfg(not(windows))]
    let s = "tauri://localhost/error.html";
    Url::parse(s).expect("valid")
}

fn is_error_page(u: &Url) -> bool {
    let e = error_page();
    u.scheme() == e.scheme() && u.host_str() == e.host_str() && u.path() == e.path()
}

/// What to do with a navigation of the console window.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Navigation {
    /// Within the admin listener's origin (or the blank start page or the
    /// bundled error page): load it in the window.
    Allow,
    /// An http or https page of another origin: open it in the default
    /// browser and keep the window where it is.
    OpenInBrowser,
    /// Anything else (other schemes, credentials in the URL): refuse.
    Refuse,
}

pub fn decide(u: &Url, admin: &AdminOrigin) -> Navigation {
    if u.as_str() == "about:blank" || admin.contains(u) || is_error_page(u) {
        return Navigation::Allow;
    }
    if matches!(u.scheme(), "http" | "https") && u.username().is_empty() && u.password().is_none() && u.host().is_some()
    {
        return Navigation::OpenInBrowser;
    }
    Navigation::Refuse
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::claims;

    fn admin() -> AdminOrigin {
        AdminOrigin::parse("https://127.0.0.1:8444").unwrap()
    }

    #[test]
    fn the_window_stays_on_the_admin_origin() {
        claims::partial(&["FR-20.6", "SR-2-6"]);
        let a = admin();
        for (u, want) in [
            ("https://127.0.0.1:8444/", Navigation::Allow),
            (
                "https://127.0.0.1:8444/approvals/0b0e5c1e-2f0e-4a7b-9a51-6d5f8e7c1a2b",
                Navigation::Allow,
            ),
            ("about:blank", Navigation::Allow),
            (
                "https://github.com/ethan03805/Secure-MCP-Gateway/blob/main/docs/console.md",
                Navigation::OpenInBrowser,
            ),
            ("http://example.com/", Navigation::OpenInBrowser),
            ("https://127.0.0.1:8445/", Navigation::OpenInBrowser),
            (concat!("https://127.0.0.1:8444", "@evil.example/"), Navigation::Refuse),
            ("javascript:alert(1)", Navigation::Refuse),
            ("data:text/html,<script>alert(1)</script>", Navigation::Refuse),
            ("file:///etc/passwd", Navigation::Refuse),
            ("tauri://localhost/settings.html", Navigation::Refuse),
            ("smcp://approvals", Navigation::Refuse),
            ("blob:https://127.0.0.1:8444/abc", Navigation::Refuse),
        ] {
            assert_eq!(decide(&Url::parse(u).unwrap(), &a), want, "{u}");
        }
        assert_eq!(decide(&error_page(), &a), Navigation::Allow);
    }

    #[test]
    fn approvals_open_at_g13() {
        claims::partial(&["FR-20.7", "SR-2.6-2"]);
        assert_eq!(
            admin().page(&Page::Approvals.path()).as_str(),
            "https://127.0.0.1:8444/approvals"
        );
        assert_eq!(admin().page(&Page::Home.path()).as_str(), "https://127.0.0.1:8444/");
        let id = ApprovalId::parse("0B0E5C1E-2F0E-4A7B-9A51-6D5F8E7C1A2B").unwrap();
        assert_eq!(
            admin().page(&Page::Approval(id).path()).as_str(),
            "https://127.0.0.1:8444/approvals/0b0e5c1e-2f0e-4a7b-9a51-6d5f8e7c1a2b"
        );
        for bad in [
            "",
            "0b0e5c1e2f0e4a7b9a516d5f8e7c1a2b",
            "0b0e5c1e-2f0e-4a7b-9a51-6d5f8e7c1a2g",
            "0b0e5c1e-2f0e-4a7b-9a51-6d5f8e7c1a2b0",
            "../../admin/v1/stop/0000000000000000",
        ] {
            assert!(ApprovalId::parse(bad).is_none(), "{bad}");
        }
    }

    #[test]
    fn the_window_is_incognito_without_devtools() {
        claims::partial(&["SR-2-4"]);
        const { assert!(WINDOW.incognito) };
        const { assert!(!WINDOW.devtools) };
        assert_eq!(WINDOW.label, "console");
    }

    #[test]
    fn the_error_page_offers_no_way_to_proceed() {
        claims::partial(&["SR-2.8-5"]);
        let page = include_str!("../../src/error.html");
        let lower = page.to_lowercase();
        for forbidden in ["<script", "<a ", "<button", "<form", "onclick", "http://", "https://"] {
            assert!(!lower.contains(forbidden), "error page contains {forbidden}");
        }
        assert!(page.contains("Content-Security-Policy"));
    }
}
