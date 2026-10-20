//! The bundled ContextForge choice of the first-run setup (SRS FR-22.44,
//! desktop part). The setup window shows it as a checkbox that starts
//! unchecked (`src/contextforge-choice.ts`). Only a checked box adds
//! `--with-contextforge` to `smcpctl install`, which writes
//! `[contextforge] bundled = true` and fetches the pinned image; without
//! it, install writes `bundled = false` (FR-22.22). The retry command a
//! failed setup shows carries the same choice.

/// The `smcpctl install` flag that enables the bundled instance.
pub const FLAG: &str = "--with-contextforge";

/// Adds the flag to an installation command when the operator chose it.
pub fn with_choice(mut argv: Vec<String>, enabled: bool) -> Vec<String> {
    if enabled {
        argv.push(FLAG.into());
    }
    argv
}

/// The retry command of a failed setup with the operator's choice.
pub fn retry(command: String, enabled: bool) -> String {
    if enabled {
        format!("{command} {FLAG}")
    } else {
        command
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::claims;
    use crate::setup::{install_argv, retry_command, Exit, Profile, Progress, SecretFiles};
    use std::path::Path;

    fn files() -> SecretFiles {
        // Paths that do not exist: dropping the value removes nothing.
        let dir = std::path::PathBuf::from("/nonexistent-smcp-contextforge-test");
        SecretFiles {
            admin: dir.join("a"),
            approver: dir.join("b"),
            dir,
        }
    }

    #[test]
    fn flag_only_when_chosen() {
        claims::partial(&["FR-22.44", "FR-22.22"]);
        for profile in [Profile::Standalone, Profile::Enforced] {
            let base = install_argv(Path::new("/usr/bin/smcpctl"), profile, &files());
            assert!(!base.iter().any(|a| a == FLAG), "the default adds no flag");
            assert_eq!(with_choice(base.clone(), false), base);
            let yes = with_choice(base.clone(), true);
            assert_eq!(yes.len(), base.len() + 1);
            assert_eq!(yes.last().map(String::as_str), Some(FLAG));
            assert_eq!(yes.iter().filter(|a| a.as_str() == FLAG).count(), 1);
        }
    }

    #[test]
    fn retry_carries_the_choice() {
        claims::partial(&["FR-22.44"]);
        let mut p = Progress::start(Profile::Standalone);
        p.finish(&Exit {
            code: Some(1),
            ..Default::default()
        });
        let f = p.failure.clone().unwrap();
        assert_eq!(f.retry, retry_command(Profile::Standalone));

        let mut p = Progress::start(Profile::Standalone);
        p.contextforge = true;
        p.finish(&Exit {
            code: Some(1),
            ..Default::default()
        });
        let f = p.failure.unwrap();
        assert_eq!(f.retry, format!("{} {FLAG}", retry_command(Profile::Standalone)));
    }

    #[test]
    fn progress_reports_the_choice_off_by_default() {
        claims::partial(&["FR-22.44"]);
        let p = Progress::default();
        assert!(!p.contextforge);
        let v = serde_json::to_value(&p).unwrap();
        assert_eq!(v["contextforge"], serde_json::Value::Bool(false));
    }
}
