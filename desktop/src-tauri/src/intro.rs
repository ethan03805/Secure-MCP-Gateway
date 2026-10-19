//! The first-run introduction's stored state (SRS FR-20.41, FR-20.42): one
//! flag, `completed` or `skipped`, in the file `introduction` beside the
//! desktop settings. Nothing else about the introduction is stored, and it
//! sends nothing anywhere.

use std::path::Path;

/// The file name of the flag in the application's configuration directory.
pub const FLAG_FILE: &str = "introduction";

/// How the user left the introduction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Flag {
    Completed,
    Skipped,
}

impl Flag {
    pub fn as_str(self) -> &'static str {
        match self {
            Flag::Completed => "completed",
            Flag::Skipped => "skipped",
        }
    }

    /// Parses the value the Introduction window sends or the file holds.
    pub fn parse(s: &str) -> Option<Flag> {
        match s.trim() {
            "completed" => Some(Flag::Completed),
            "skipped" => Some(Flag::Skipped),
            _ => None,
        }
    }
}

/// The stored flag, or None when the introduction was never left (or the
/// file is unreadable or holds anything else, so it shows again).
pub fn load(dir: &Path) -> Option<Flag> {
    std::fs::read_to_string(dir.join(FLAG_FILE))
        .ok()
        .and_then(|s| Flag::parse(&s))
}

/// Stores the flag, creating the directory if needed.
pub fn save(dir: &Path, flag: Flag) -> std::io::Result<()> {
    std::fs::create_dir_all(dir)?;
    std::fs::write(dir.join(FLAG_FILE), flag.as_str())
}

/// Whether the introduction opens when the application starts (FR-20.41).
pub fn show_at_start(flag: Option<Flag>) -> bool {
    flag.is_none()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::claims::partial;

    fn tmp(name: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("smcp-intro-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        d
    }

    #[test]
    fn shows_until_completed_or_skipped() {
        partial(&["FR-20.41"]);
        let d = tmp("flag");
        assert!(show_at_start(load(&d)), "a new user sees the introduction");
        for flag in [Flag::Completed, Flag::Skipped] {
            save(&d, flag).unwrap();
            assert_eq!(load(&d), Some(flag));
            assert!(!show_at_start(load(&d)), "{flag:?}: not shown again at start");
        }
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn only_the_flag_is_stored() {
        partial(&["FR-20.42"]);
        let d = tmp("only");
        save(&d, Flag::Skipped).unwrap();
        let names: Vec<_> = std::fs::read_dir(&d).unwrap().map(|e| e.unwrap().file_name()).collect();
        assert_eq!(names, vec![std::ffi::OsString::from(FLAG_FILE)]);
        assert_eq!(std::fs::read_to_string(d.join(FLAG_FILE)).unwrap(), "skipped");
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn anything_else_shows_the_introduction_again() {
        let d = tmp("junk");
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(d.join(FLAG_FILE), "maybe").unwrap();
        assert_eq!(load(&d), None);
        assert_eq!(Flag::parse(" completed\n"), Some(Flag::Completed));
        assert_eq!(Flag::parse("Completed"), None);
        std::fs::remove_dir_all(&d).unwrap();
    }
}
