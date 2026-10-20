//! Tray state explanations (SRS FR-20.45) from the shared message catalogue
//! `docs/design/messages.json` (FR-20.48), compiled in: the tray menu's
//! status lines and the Gateway Status window show the same text, and the
//! console shows the catalogue's reason-code messages.

use std::sync::OnceLock;

use serde::Deserialize;

use crate::state::{TrayState, TrayView};

const CATALOGUE: &str = include_str!("../../../docs/design/messages.json");

#[derive(Debug, Clone, Deserialize)]
pub struct StateText {
    pub label: String,
    pub meaning: String,
    pub action: String,
    #[serde(default)]
    pub detail: Option<String>,
    pub control: String,
}

#[derive(Debug, Deserialize)]
struct Label {
    meaning: String,
}

#[derive(Debug, Deserialize)]
struct Desktop {
    states: std::collections::HashMap<String, StateText>,
    labels: std::collections::HashMap<String, Label>,
}

#[derive(Debug, Deserialize)]
struct Catalogue {
    desktop: Desktop,
}

fn catalogue() -> &'static Catalogue {
    static C: OnceLock<Catalogue> = OnceLock::new();
    // The catalogue is compiled in and checked by the tests below and by
    // internal/edge.TestMessageCatalogue, so a parse failure is a build defect.
    C.get_or_init(|| serde_json::from_str(CATALOGUE).expect("docs/design/messages.json is valid"))
}

/// The catalogue key of a state: FR-20.2's name with a hyphen for the space.
pub fn key(state: TrayState) -> &'static str {
    match state {
        TrayState::Healthy => "healthy",
        TrayState::Running => "running",
        TrayState::Degraded => "degraded",
        TrayState::FailClosed => "fail-closed",
        TrayState::EmergencyStop => "emergency-stop",
        TrayState::Stopped => "stopped",
        TrayState::Unreachable => "unreachable",
    }
}

/// The explanation of a state. A degraded Gateway that is not labelled
/// enforced gets the Standalone explanation (a cause besides the profile's
/// own); one degraded only by the profile's own cause is `Running`.
pub fn state_text(state: TrayState, not_enforced: bool) -> &'static StateText {
    let k = if state == TrayState::Degraded && not_enforced {
        "degraded-not-enforced"
    } else {
        key(state)
    };
    &catalogue().desktop.states[k]
}

/// What the `not enforced` label means.
pub fn not_enforced_meaning() -> &'static str {
    &catalogue().desktop.labels["not-enforced"].meaning
}

/// The two status lines at the top of the tray menu (FR-20.45): the state's
/// name, with `not enforced` where it applies, and the first sentence of
/// what the state means.
pub fn status_lines(view: &TrayView) -> (String, String) {
    let t = state_text(view.state, view.not_enforced);
    let mut title = t.label.clone();
    if view.not_enforced && !matches!(view.state, TrayState::Stopped | TrayState::Unreachable) {
        title.push_str(", not enforced");
    }
    let first = match t.meaning.find(". ") {
        Some(i) => &t.meaning[..=i],
        None => t.meaning.as_str(),
    };
    (title, first.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::claims::partial;

    #[test]
    fn every_state_has_an_explanation() {
        partial(&["FR-20.45", "FR-20.48"]);
        for s in TrayState::ALL {
            for ne in [false, true] {
                let t = state_text(s, ne);
                assert!(
                    !t.label.is_empty() && !t.meaning.is_empty() && !t.action.is_empty(),
                    "{s:?}"
                );
                assert!(
                    ["open-console", "start", "restart"].contains(&t.control.as_str()),
                    "{s:?}"
                );
            }
            assert_eq!(key(s), s.name().replace(' ', "-"), "catalogue key of {s:?}");
        }
        assert_eq!(state_text(TrayState::Stopped, false).control, "start");
        for s in [
            TrayState::FailClosed,
            TrayState::EmergencyStop,
            TrayState::Degraded,
            TrayState::Running,
        ] {
            assert_eq!(state_text(s, false).control, "open-console", "{s:?}");
        }
        assert!(state_text(TrayState::Unreachable, false)
            .detail
            .as_deref()
            .unwrap_or("")
            .contains("{lastReading}"));
        assert!(!not_enforced_meaning().is_empty());
    }

    #[test]
    fn standalone_degraded_is_explained() {
        let a = state_text(TrayState::Degraded, true);
        let b = state_text(TrayState::Degraded, false);
        assert!(a.meaning.contains("Standalone"));
        assert_ne!(a.meaning, b.meaning);
    }

    #[test]
    fn status_lines_name_the_state_and_one_sentence() {
        partial(&["FR-20.45"]);
        let v = TrayView {
            state: TrayState::FailClosed,
            not_enforced: true,
            pending: None,
        };
        let (title, line) = status_lines(&v);
        assert_eq!(title, "Fail-closed, not enforced");
        assert!(line.ends_with('.') && !line.contains(". "), "{line}");
        let (title, line) = status_lines(&TrayView {
            state: TrayState::Running,
            not_enforced: true,
            pending: Some(0),
        });
        assert_eq!(title, "Running, not enforced");
        assert!(!line.contains("degraded"), "{line}");
        let (title, _) = status_lines(&TrayView {
            state: TrayState::Unreachable,
            not_enforced: true,
            pending: None,
        });
        assert_eq!(title, "Unreachable");
    }
}
