//! Deep links (SRS FR-20.28, SEC 8.9).
//!
//! The application registers the URL scheme `smcp` and nothing else
//! (`plugins.deep-link.desktop.schemes` in tauri.conf.json, which the Tauri
//! bundler writes into the macOS Info.plist, the Linux desktop entry and
//! the Windows installer). It accepts exactly three forms:
//!
//! - `smcp://console`
//! - `smcp://approvals`
//! - `smcp://approvals/<approval ID>`, the ID a UUID
//!
//! An accepted link only brings the console window to the page it names,
//! where the user still signs in and decides. Every other link, including
//! one with a query, a fragment, user information, a port, another path,
//! a malformed ID or more than [`MAX_LEN`] bytes, is ignored before any
//! request is made: any web page can open a registered scheme, so a link
//! never carries an action.

use crate::console::{ApprovalId, Page};

/// The only scheme the application registers.
pub const SCHEME: &str = "smcp";
/// The longest accepted link is `smcp://approvals/` plus a 36-character
/// UUID (53 bytes); anything much longer is refused before parsing.
pub const MAX_LEN: usize = 64;

/// The console page an accepted link names, or None for every other link.
pub fn parse(link: &str) -> Option<Page> {
    if link.len() > MAX_LEN {
        return None;
    }
    // Exact, case-sensitive prefix: no `SMCP:`, no `smcp:/approvals`.
    let rest = link.strip_prefix("smcp://")?;
    match rest {
        "console" => Some(Page::Home),
        "approvals" => Some(Page::Approvals),
        _ => {
            let id = rest.strip_prefix("approvals/")?;
            ApprovalId::parse(id).map(Page::Approval)
        }
    }
}

/// The first accepted link among a process's arguments (Linux and Windows
/// pass the link as an argument to the application). Arguments that are
/// not `smcp:` links are not links and are skipped; a refused link is
/// ignored.
pub fn from_args<I, S>(args: I) -> Option<Page>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    args.into_iter()
        .map(|a| a.as_ref().to_string())
        .filter(|a| a.get(..5).is_some_and(|p| p.eq_ignore_ascii_case("smcp:")))
        .find_map(|a| parse(&a))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::claims;

    const ID: &str = "0b0e5c1e-2f0e-4a7b-9a51-6d5f8e7c1a2b";

    #[test]
    fn accepts_exactly_the_three_forms() {
        claims::partial(&["FR-20.28"]);
        assert_eq!(parse("smcp://console"), Some(Page::Home));
        assert_eq!(parse("smcp://approvals"), Some(Page::Approvals));
        let p = parse(&format!("smcp://approvals/{ID}")).unwrap();
        assert_eq!(p.path(), format!("/approvals/{ID}"));
        // Upper-case hex is the same UUID.
        assert_eq!(parse(&format!("smcp://approvals/{}", ID.to_uppercase())), Some(p));
    }

    #[test]
    fn ignores_every_other_link() {
        claims::partial(&["FR-20.28", "SR-2.6-2"]);
        let long = format!("smcp://approvals/{}", "a".repeat(64 * 1024));
        for bad in [
            "smcp://console/",
            "smcp://console?next=https://evil.example/",
            "smcp://approvals?approve=1",
            "smcp://approvals#x",
            "smcp://approvals/",
            "smcp://approvals/not-a-uuid",
            "smcp://approvals/0b0e5c1e2f0e4a7b9a516d5f8e7c1a2b",
            "smcp://approvals/0b0e5c1e-2f0e-4a7b-9a51-6d5f8e7c1a2b/approve",
            "smcp://approvals/0b0e5c1e-2f0e-4a7b-9a51-6d5f8e7c1a2b?decision=allow",
            "smcp://user@console",
            "smcp://console:8444",
            "smcp://settings",
            "smcp://stop",
            "smcp:console",
            "smcp:/approvals",
            "SMCP://console",
            "smcps://console",
            "https://127.0.0.1:8444/approvals",
            "javascript:alert(1)",
            "",
            long.as_str(),
        ] {
            assert_eq!(parse(bad), None, "{bad:.80}");
        }
    }

    #[test]
    fn links_arrive_as_arguments_on_linux_and_windows() {
        claims::partial(&["FR-20.28"]);
        let exe = "/usr/bin/smcp-desktop";
        assert_eq!(from_args([exe]), None);
        assert_eq!(from_args([exe, "smcp://approvals"]), Some(Page::Approvals));
        assert_eq!(from_args([exe, "--flag", "smcp://console"]), Some(Page::Home));
        assert_eq!(
            from_args([exe, "smcp://stop", "smcp://approvals"]),
            Some(Page::Approvals)
        );
        assert_eq!(from_args([exe, "smcp://approvals?x=1"]), None);
        assert_eq!(from_args([exe, "é"]), None);
    }
}
