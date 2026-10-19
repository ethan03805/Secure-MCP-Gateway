//! Client setup (SRS FR-20.10, FR-15.1, FR-15.11, SR-2-3, SR-2-5, F-103,
//! I-42).
//!
//! The Set Up a Client window is a front end to `smcpctl connect` (the
//! alias of `smcpctl clients setup`): it lists the Appendix K clients that
//! `smcpctl clients detect` finds on this computer, shows the changes
//! `smcpctl connect <client> --dry-run --json` reports, applies them only
//! after the user confirms that exact preview, and offers the client's
//! lockdown profile and removal (`--remove`) in the same window. Every
//! command is a fixed argument vector; the client ID is one `smcpctl`
//! itself listed, and the commands run in the user's home directory so
//! that no project-scope file of some other directory is touched.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::service::Host;
use crate::setup::{self, Exit};

/// Detection and previews read files only; applying writes a few.
pub const TIMEOUT: Duration = Duration::from_secs(60);
const MAX_OUTPUT: usize = 256 * 1024;

/// One client as `smcpctl clients detect --json` reports it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Client {
    pub id: String,
    pub name: String,
    pub installed: bool,
    pub connected: bool,
    pub lockdown: bool,
    pub lockdown_available: bool,
}

#[derive(Deserialize)]
struct DetectOut {
    clients: Vec<Client>,
}

/// One file change of a preview.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Change {
    pub path: String,
    pub scope: String,
    pub purpose: String,
    pub action: String,
    pub content: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Plan {
    pub changes: Vec<Change>,
    pub commands: Vec<Vec<String>>,
    pub notes: Vec<String>,
}

/// What `smcpctl connect <client> --dry-run --json` reports.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Preview {
    pub client: String,
    pub name: String,
    pub setup: Plan,
    pub lockdown: Option<Plan>,
}

/// A client ID as smcpctl writes them: lower-case letters and hyphens.
pub fn valid_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 32
        && id.starts_with(|c: char| c.is_ascii_lowercase())
        && id.chars().all(|c| c.is_ascii_lowercase() || c == '-')
}

/// The Gateway configuration `smcpctl connect` needs: the first one that
/// exists on this host, by path only (the application never reads it).
pub fn config_path(h: &Host) -> Option<PathBuf> {
    setup::config_paths(h).into_iter().find(|p| p.exists())
}

fn s(p: &Path) -> String {
    p.display().to_string()
}

pub fn detect_argv(smcpctl: &Path) -> Vec<String> {
    vec![s(smcpctl), "clients".into(), "detect".into(), "--json".into()]
}

fn connect_base(smcpctl: &Path, cfg: &Path, id: &str) -> Vec<String> {
    vec![s(smcpctl), "connect".into(), id.into(), "--config".into(), s(cfg)]
}

pub fn preview_argv(smcpctl: &Path, cfg: &Path, id: &str, lockdown: bool) -> Vec<String> {
    let mut v = connect_base(smcpctl, cfg, id);
    v.extend(["--dry-run".into(), "--json".into()]);
    if !lockdown {
        v.push("--no-lockdown".into());
    }
    v
}

pub fn apply_argv(smcpctl: &Path, cfg: &Path, id: &str, lockdown: bool) -> Vec<String> {
    let mut v = connect_base(smcpctl, cfg, id);
    if !lockdown {
        v.push("--no-lockdown".into());
    }
    v
}

pub fn remove_argv(smcpctl: &Path, cfg: &Path, id: &str) -> Vec<String> {
    let mut v = connect_base(smcpctl, cfg, id);
    v.push("--remove".into());
    v
}

/// The command as a user would type it, for the details area.
pub fn shown(argv: &[String]) -> String {
    let mut v = argv.to_vec();
    if let Some(first) = v.first_mut() {
        *first = "smcpctl".into();
    }
    v.join(" ")
}

/// A command's result.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Outcome {
    pub ok: bool,
    /// The message-catalogue code of a failure.
    pub code: Option<&'static str>,
    pub command: String,
    pub detail: String,
    pub output: String,
}

/// Runs a fixed command in `dir` and collects its output.
pub fn run(argv: &[String], dir: &Path) -> (Exit, String) {
    let out = Arc::new(Mutex::new(String::new()));
    let o = out.clone();
    let exit = setup::run_streaming_in(
        argv,
        Some(dir),
        TIMEOUT,
        Arc::new(move |l: &str| {
            let mut g = o.lock().unwrap_or_else(|e| e.into_inner());
            if g.len() < MAX_OUTPUT {
                g.push_str(l);
                g.push('\n');
            }
        }),
    );
    let g = out.lock().unwrap_or_else(|e| e.into_inner()).clone();
    (exit, g)
}

/// Explains how a command ended (FR-20.47: no bare exit status).
pub fn explain(exit: &Exit) -> String {
    if let Some(e) = &exit.spawn_error {
        format!("smcpctl could not be started: {e}")
    } else if exit.timed_out {
        format!(
            "smcpctl did not finish within {} seconds and was stopped.",
            TIMEOUT.as_secs()
        )
    } else {
        match exit.code {
            Some(0) => "smcpctl finished without an error.".into(),
            Some(c) => format!(
                "smcpctl exited with status {c}, which means it stopped at an error. Its output names the cause."
            ),
            None => "smcpctl was stopped by a signal before it finished.".into(),
        }
    }
}

pub fn outcome(argv: &[String], exit: &Exit, output: String, failure: &'static str) -> Outcome {
    let ok = exit.code == Some(0) && !exit.timed_out && exit.spawn_error.is_none();
    Outcome {
        ok,
        code: (!ok).then_some(failure),
        command: shown(argv),
        detail: explain(exit),
        output,
    }
}

/// Parses `clients detect --json` from a command's combined output: the
/// JSON object is the output from its first `{`.
pub fn parse_detect(out: &str) -> Option<Vec<Client>> {
    let at = out.find('{')?;
    serde_json::from_str::<DetectOut>(out[at..].trim())
        .ok()
        .map(|d| d.clients)
}

pub fn parse_preview(out: &str) -> Option<Preview> {
    let at = out.find('{')?;
    serde_json::from_str::<Preview>(out[at..].trim()).ok()
}

/// What the window has shown, so that only a previewed plan is applied.
#[derive(Default)]
pub struct Session {
    pub known: Mutex<Vec<String>>,
    pub previewed: Mutex<Option<(String, bool)>>,
}

impl Session {
    /// Whether `id` is a client the last detection listed.
    pub fn is_known(&self, id: &str) -> bool {
        valid_id(id)
            && self
                .known
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .iter()
                .any(|k| k == id)
    }

    /// Whether the user saw the preview of exactly this setup.
    pub fn was_previewed(&self, id: &str, lockdown: bool) -> bool {
        self.previewed.lock().unwrap_or_else(|e| e.into_inner()).as_ref() == Some(&(id.to_string(), lockdown))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::claims;

    #[test]
    fn commands_are_fixed_and_use_the_connect_alias() {
        claims::partial(&["FR-20.10", "SR-2-5"]);
        let smcpctl = Path::new("/usr/bin/smcpctl");
        let cfg = Path::new("/home/u/.config/smcp-gateway/smcp.toml");
        assert_eq!(
            detect_argv(smcpctl),
            ["/usr/bin/smcpctl", "clients", "detect", "--json"]
        );
        assert_eq!(
            preview_argv(smcpctl, cfg, "codex", true),
            [
                "/usr/bin/smcpctl",
                "connect",
                "codex",
                "--config",
                "/home/u/.config/smcp-gateway/smcp.toml",
                "--dry-run",
                "--json"
            ]
        );
        assert_eq!(
            preview_argv(smcpctl, cfg, "codex", false).last().unwrap(),
            "--no-lockdown"
        );
        let apply = apply_argv(smcpctl, cfg, "claude-code", true);
        assert!(!apply.iter().any(|a| a == "--dry-run" || a == "--no-lockdown"));
        assert_eq!(
            apply_argv(smcpctl, cfg, "claude-code", false).last().unwrap(),
            "--no-lockdown"
        );
        assert_eq!(remove_argv(smcpctl, cfg, "codex").last().unwrap(), "--remove");
        assert_eq!(
            shown(&remove_argv(smcpctl, cfg, "codex")),
            "smcpctl connect codex --config /home/u/.config/smcp-gateway/smcp.toml --remove"
        );
    }

    #[test]
    fn only_listed_client_ids_are_used() {
        claims::partial(&["FR-20.10", "SR-2-5"]);
        for good in ["claude-code", "codex", "gemini-cli"] {
            assert!(valid_id(good), "{good}");
        }
        for bad in [
            "",
            "-x",
            "Codex",
            "codex;rm",
            "../codex",
            "codex --remove",
            &"a".repeat(33),
        ] {
            assert!(!valid_id(bad), "{bad}");
        }
        let s = Session::default();
        assert!(!s.is_known("codex"));
        *s.known.lock().unwrap() = vec!["codex".into()];
        assert!(s.is_known("codex") && !s.is_known("claude-code"));
        assert!(!s.was_previewed("codex", true));
        *s.previewed.lock().unwrap() = Some(("codex".into(), true));
        assert!(s.was_previewed("codex", true));
        // A preview without the lockdown does not cover a setup with it.
        assert!(!s.was_previewed("codex", false));
    }

    #[test]
    fn detection_and_previews_parse() {
        claims::partial(&["FR-20.10"]);
        let d = parse_detect(
            r#"{"clients":[{"id":"claude-code","name":"Claude Code","installed":true,"connected":false,"lockdown":false,"lockdownAvailable":true}]}"#,
        )
        .unwrap();
        assert_eq!(d[0].name, "Claude Code");
        assert!(d[0].installed && d[0].lockdown_available);
        assert!(parse_detect("smcpctl: no such command").is_none());
        let p = parse_preview(
            r#"{"client":"codex","name":"Codex CLI","setup":{"changes":[{"path":"/h/.codex/config.toml","scope":"user","purpose":"MCP server","action":"create","content":"x"}],"commands":[],"notes":[]},"lockdown":null}"#,
        )
        .unwrap();
        assert_eq!(p.setup.changes[0].action, "create");
        assert!(p.lockdown.is_none());
    }

    #[test]
    fn failures_are_explained_with_their_code() {
        claims::partial(&["FR-20.10", "FR-20.47"]);
        let argv = vec!["/usr/bin/smcpctl".to_string(), "connect".into(), "codex".into()];
        let o = outcome(
            &argv,
            &Exit {
                code: Some(1),
                ..Default::default()
            },
            "smcpctl: lockdown: permission denied\n".into(),
            "CLIENT_SETUP_FAILED",
        );
        assert!(!o.ok);
        assert_eq!(o.code, Some("CLIENT_SETUP_FAILED"));
        assert_eq!(o.command, "smcpctl connect codex");
        assert!(o.detail.contains("status 1, which means"));
        let ok = outcome(
            &argv,
            &Exit {
                code: Some(0),
                ..Default::default()
            },
            String::new(),
            "CLIENT_SETUP_FAILED",
        );
        assert!(ok.ok && ok.code.is_none());
        assert!(explain(&Exit {
            timed_out: true,
            ..Default::default()
        })
        .contains("60 seconds"));
    }

    #[cfg(unix)]
    #[test]
    fn commands_run_in_the_given_directory() {
        claims::partial(&["FR-20.10"]);
        let dir = std::env::temp_dir().join(format!("smcp-desktop-clients-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let (exit, out) = run(&["/bin/pwd".to_string()], &dir);
        assert_eq!(exit.code, Some(0));
        assert_eq!(
            std::fs::canonicalize(out.trim()).unwrap(),
            std::fs::canonicalize(&dir).unwrap()
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
