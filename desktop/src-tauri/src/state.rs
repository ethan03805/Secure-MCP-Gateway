//! Tray state (SRS FR-20.2, FR-20.4): which of the six states the tray
//! shows, computed from the latest metrics reads and the service manager's
//! view of the service. Stale data never reads as healthy: when no
//! exposition has been read for [`STALE_AFTER`], the state is
//! `unreachable`.

use std::time::{Duration, Instant};

use crate::health::Exposition;

/// No exposition read for this long means `unreachable` (FR-20.4).
pub const STALE_AFTER: Duration = Duration::from_secs(15);
/// How often the tray reads the metrics endpoint (FR-20.4: at least every
/// 5 seconds; every 2 keeps a change within the 10-second bound).
pub const POLL_INTERVAL: Duration = Duration::from_secs(2);

/// The six tray states of FR-20.2.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TrayState {
    Healthy,
    Degraded,
    FailClosed,
    EmergencyStop,
    Stopped,
    Unreachable,
}

impl TrayState {
    pub const ALL: [TrayState; 6] = [
        TrayState::Healthy,
        TrayState::Degraded,
        TrayState::FailClosed,
        TrayState::EmergencyStop,
        TrayState::Stopped,
        TrayState::Unreachable,
    ];

    /// The state's name as FR-20.2 spells it.
    pub fn name(self) -> &'static str {
        match self {
            TrayState::Healthy => "healthy",
            TrayState::Degraded => "degraded",
            TrayState::FailClosed => "fail-closed",
            TrayState::EmergencyStop => "emergency stop",
            TrayState::Stopped => "stopped",
            TrayState::Unreachable => "unreachable",
        }
    }
}

/// The service manager's view of the `smcpd` service.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceStatus {
    /// Loaded or active in the service manager.
    Running,
    /// Installed but not loaded or not active.
    Stopped,
    /// No service unit is installed for this user or system.
    NotInstalled,
    /// The service manager could not be asked.
    Unknown,
}

/// What the tray shows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrayView {
    pub state: TrayState,
    /// Whether to show the `not enforced` label (FR-20.4): shown unless the
    /// exposition reports the release label `enforced`.
    pub not_enforced: bool,
    /// The pending-approval count, when known from fresh data.
    pub pending: Option<u64>,
}

impl TrayView {
    /// The accessible name of the tray icon (and its tooltip).
    pub fn accessible_name(&self) -> String {
        let mut s = format!("Secure MCP Gateway: {}", self.state.name());
        if self.not_enforced {
            s.push_str(" (not enforced)");
        }
        if let Some(n) = self.pending.filter(|n| *n > 0) {
            s.push_str(&format!(", {n} pending approval{}", if n == 1 { "" } else { "s" }));
        }
        s
    }

    /// The short text shown beside the icon.
    pub fn label(&self) -> String {
        if self.not_enforced && !matches!(self.state, TrayState::Stopped | TrayState::Unreachable) {
            "not enforced".to_string()
        } else {
            String::new()
        }
    }
}

/// Keeps the latest reads and computes the view.
#[derive(Debug, Default)]
pub struct Monitor {
    last_ok: Option<(Instant, Exposition)>,
    last_attempt_failed: bool,
}

impl Monitor {
    pub fn record_ok(&mut self, at: Instant, e: Exposition) {
        self.last_ok = Some((at, e));
        self.last_attempt_failed = false;
    }

    pub fn record_failure(&mut self) {
        self.last_attempt_failed = true;
    }

    /// The pending count of the latest successful read, if any.
    pub fn last_pending(&self) -> Option<u64> {
        self.last_ok.as_ref().map(|(_, e)| e.pending_approvals)
    }

    pub fn view(&self, now: Instant, service: ServiceStatus) -> TrayView {
        let fresh = self
            .last_ok
            .as_ref()
            .filter(|(at, _)| now.saturating_duration_since(*at) < STALE_AFTER);
        // A service the manager reports stopped, with the latest read
        // failing, is stopped now; it does not wait for the stale bound.
        if (self.last_attempt_failed || self.last_ok.is_none())
            && matches!(service, ServiceStatus::Stopped | ServiceStatus::NotInstalled)
        {
            return TrayView {
                state: TrayState::Stopped,
                not_enforced: true,
                pending: None,
            };
        }
        match fresh {
            None => TrayView {
                state: TrayState::Unreachable,
                not_enforced: true,
                pending: None,
            },
            Some((_, e)) => {
                let state = if e.emergency_stop == Some(true) {
                    TrayState::EmergencyStop
                } else {
                    match e.health_state {
                        0 => TrayState::Healthy,
                        1 => TrayState::Degraded,
                        _ => TrayState::FailClosed,
                    }
                };
                TrayView {
                    state,
                    not_enforced: e.release_enforced != Some(true),
                    pending: Some(e.pending_approvals),
                }
            }
        }
    }
}

/// Which of Start, Stop and Restart are enabled (FR-20.2): Start only while
/// the service is stopped, Stop and Restart only while it runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ServiceItems {
    pub start: bool,
    pub stop: bool,
    pub restart: bool,
}

pub fn service_items(s: ServiceStatus) -> ServiceItems {
    let running = s == ServiceStatus::Running;
    ServiceItems {
        start: s == ServiceStatus::Stopped,
        stop: running,
        restart: running,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::claims;
    use crate::health::{self, tests::fake_endpoint};

    fn expo(health: u8, pending: u64, enforced: Option<bool>, stop: Option<bool>) -> Exposition {
        Exposition {
            health_state: health,
            pending_approvals: pending,
            release_enforced: enforced,
            emergency_stop: stop,
        }
    }

    #[test]
    fn six_states_from_metrics_and_service() {
        claims::partial(&["FR-20.2", "FR-20.4"]);
        let t0 = Instant::now();
        let mut m = Monitor::default();
        assert_eq!(m.view(t0, ServiceStatus::Running).state, TrayState::Unreachable);
        assert_eq!(m.view(t0, ServiceStatus::Stopped).state, TrayState::Stopped);
        for (e, want) in [
            (expo(0, 0, Some(true), Some(false)), TrayState::Healthy),
            (expo(1, 0, Some(true), Some(false)), TrayState::Degraded),
            (expo(2, 0, Some(true), Some(false)), TrayState::FailClosed),
            (expo(0, 0, Some(true), Some(true)), TrayState::EmergencyStop),
            (expo(2, 0, Some(true), Some(true)), TrayState::EmergencyStop),
        ] {
            m.record_ok(t0, e);
            assert_eq!(m.view(t0, ServiceStatus::Running).state, want);
        }
        // The service manager says stopped and the endpoint stopped answering.
        m.record_failure();
        assert_eq!(
            m.view(t0 + Duration::from_secs(1), ServiceStatus::Stopped).state,
            TrayState::Stopped
        );
        // Each state has a distinct name.
        let names: std::collections::HashSet<_> = TrayState::ALL.iter().map(|s| s.name()).collect();
        assert_eq!(names.len(), 6);
    }

    #[test]
    fn stale_data_is_unreachable_never_healthy() {
        claims::partial(&["FR-20.4"]);
        let t0 = Instant::now();
        let mut m = Monitor::default();
        m.record_ok(t0, expo(0, 2, Some(true), Some(false)));
        m.record_failure();
        // Within the bound the last state stands; at 15 s it is unreachable.
        assert_eq!(
            m.view(t0 + Duration::from_secs(14), ServiceStatus::Running).state,
            TrayState::Healthy
        );
        for s in [15, 16, 60, 3600] {
            let v = m.view(t0 + Duration::from_secs(s), ServiceStatus::Running);
            assert_eq!(v.state, TrayState::Unreachable, "{s} s");
            assert_eq!(v.pending, None);
        }
        assert_eq!(
            m.view(t0 + Duration::from_secs(20), ServiceStatus::Unknown).state,
            TrayState::Unreachable
        );
    }

    #[test]
    fn not_enforced_label_unless_the_exposition_says_enforced() {
        claims::partial(&["FR-20.4"]);
        let t0 = Instant::now();
        let mut m = Monitor::default();
        for (enforced, want) in [(Some(true), false), (Some(false), true), (None, true)] {
            m.record_ok(t0, expo(0, 0, enforced, Some(false)));
            let v = m.view(t0, ServiceStatus::Running);
            assert_eq!(v.not_enforced, want, "{enforced:?}");
            assert_eq!(v.label().is_empty(), !want);
            assert_eq!(v.accessible_name().contains("(not enforced)"), want);
        }
    }

    #[test]
    fn accessible_names_state_the_state() {
        claims::partial(&["FR-20.2"]);
        for s in TrayState::ALL {
            let v = TrayView {
                state: s,
                not_enforced: false,
                pending: Some(2),
            };
            assert!(v
                .accessible_name()
                .starts_with(&format!("Secure MCP Gateway: {}", s.name())));
        }
        let v = TrayView {
            state: TrayState::Healthy,
            not_enforced: true,
            pending: Some(1),
        };
        assert_eq!(
            v.accessible_name(),
            "Secure MCP Gateway: healthy (not enforced), 1 pending approval"
        );
    }

    #[test]
    fn start_stop_restart_follow_the_service() {
        claims::partial(&["FR-20.2"]);
        assert_eq!(
            service_items(ServiceStatus::Running),
            ServiceItems {
                start: false,
                stop: true,
                restart: true
            }
        );
        assert_eq!(
            service_items(ServiceStatus::Stopped),
            ServiceItems {
                start: true,
                stop: false,
                restart: false
            }
        );
        assert_eq!(
            service_items(ServiceStatus::NotInstalled),
            ServiceItems {
                start: false,
                stop: false,
                restart: false
            }
        );
        assert_eq!(
            service_items(ServiceStatus::Unknown),
            ServiceItems {
                start: false,
                stop: false,
                restart: false
            }
        );
    }

    /// Against a live endpoint: a change shows on the next poll, and when
    /// the endpoint stops answering the state turns unreachable once 15 s
    /// have passed since the last read (time is simulated).
    #[test]
    fn poll_a_live_endpoint_then_lose_it() {
        claims::partial(&["FR-20.4"]);
        let ep = fake_endpoint(
            "smcp_health_state 0\nsmcp_pending_approvals 0\nsmcp_release_enforced 1\nsmcp_emergency_stop 0\n",
        );
        let mut m = Monitor::default();
        let t0 = Instant::now();
        let poll = |m: &mut Monitor, at: Instant| match health::read(ep.addr, Duration::from_secs(2)) {
            Ok(e) => m.record_ok(at, e),
            Err(_) => m.record_failure(),
        };
        poll(&mut m, t0);
        assert_eq!(m.view(t0, ServiceStatus::Running).state, TrayState::Healthy);
        *ep.body.lock().unwrap() = Some(
            "smcp_health_state 0\nsmcp_pending_approvals 1\nsmcp_release_enforced 1\nsmcp_emergency_stop 1\n".into(),
        );
        let t1 = t0 + POLL_INTERVAL;
        poll(&mut m, t1);
        let v = m.view(t1, ServiceStatus::Running);
        assert_eq!((v.state, v.pending), (TrayState::EmergencyStop, Some(1)));
        *ep.body.lock().unwrap() = None;
        let mut t = t1;
        while t < t1 + Duration::from_secs(20) {
            t += POLL_INTERVAL;
            poll(&mut m, t);
            let v = m.view(t, ServiceStatus::Running);
            assert_ne!(v.state, TrayState::Healthy);
            if t.duration_since(t1) >= STALE_AFTER {
                assert_eq!(v.state, TrayState::Unreachable);
            }
        }
    }
}
