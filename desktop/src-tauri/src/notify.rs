//! Approval notifications (SRS FR-20.7, SR-2.6-2, X-14).
//!
//! When the pending-approval count read from the metrics endpoint
//! increases and notifications are on, the application raises one native
//! notification. Its text is fixed except for the count: the application
//! knows nothing else without signing in, and a notification never names a
//! tool, alias or argument. It has no approve, deny or reply action;
//! activating it brings the user to the console window's Approvals view
//! (G-13), where a decision needs an Approver or Administrator sign-in.

/// One notification's text. There is no field for actions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Notice {
    pub title: &'static str,
    pub body: String,
}

pub const TITLE: &str = "Secure MCP Gateway";

/// The one action an approval notification has: its default activation
/// (a click on the notification), which opens the Approvals view. The
/// label is what a notification server that lists actions shows.
pub const OPEN_ACTION: (&str, &str) = ("default", "Open Approvals");

/// Whether a notification's reported action opens the Approvals view. A
/// dismissal (`__closed`) or anything else does nothing.
pub fn opens_approvals(action: &str) -> bool {
    action == OPEN_ACTION.0
}

/// How many notifications may wait for a click at once; each waits on a
/// thread of its own.
pub const MAX_WAITING: usize = 4;

static WAITING: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// A place among the waiting notifications, released when dropped.
#[derive(Debug)]
pub struct Waiting(());

impl Waiting {
    pub fn take() -> Option<Waiting> {
        use std::sync::atomic::Ordering;
        WAITING
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| {
                (n < MAX_WAITING).then_some(n + 1)
            })
            .ok()
            .map(|_| Waiting(()))
    }
}

impl Drop for Waiting {
    fn drop(&mut self) {
        WAITING.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
    }
}

/// The fixed text for a pending count.
pub fn notice(count: u64) -> Notice {
    let body = if count == 1 {
        "1 tool call is waiting for approval. Open the console to review it.".to_string()
    } else {
        format!("{count} tool calls are waiting for approval. Open the console to review them.")
    };
    Notice { title: TITLE, body }
}

/// Decides when to notify.
#[derive(Debug, Default)]
pub struct Notifier {
    last: u64,
}

impl Notifier {
    /// Records a fresh count and returns the notice to raise, if any: one
    /// per increase while notifications are on. The count is tracked while
    /// they are off, so turning them on does not announce old approvals.
    pub fn observe(&mut self, count: u64, enabled: bool) -> Option<Notice> {
        let increased = count > self.last;
        self.last = count;
        (increased && enabled).then(|| notice(count))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::claims;

    #[test]
    fn one_notice_per_increase_with_the_count_only() {
        claims::partial(&["FR-20.7", "SR-2.6-2"]);
        let mut n = Notifier::default();
        assert_eq!(n.observe(0, true), None);
        let first = n.observe(1, true).unwrap();
        assert_eq!(
            first.body,
            "1 tool call is waiting for approval. Open the console to review it."
        );
        assert_eq!(n.observe(1, true), None);
        assert_eq!(
            n.observe(3, true).unwrap().body,
            "3 tool calls are waiting for approval. Open the console to review them."
        );
        assert_eq!(n.observe(2, true), None);
        assert_eq!(n.observe(0, true), None);
    }

    #[test]
    fn activation_only_opens_the_approvals_view() {
        claims::partial(&["FR-20.7", "SR-2.6-2"]);
        assert!(opens_approvals("default"));
        for other in ["__closed", "approve", "deny", "reply", ""] {
            assert!(!opens_approvals(other), "{other}");
        }
        let label = OPEN_ACTION.1.to_lowercase();
        for word in ["approve", "deny", "allow", "reply"] {
            assert!(!label.contains(word), "{word}");
        }
        // The waiting threads are bounded.
        let held: Vec<_> = std::iter::from_fn(Waiting::take).take(MAX_WAITING + 2).collect();
        assert!(held.len() <= MAX_WAITING);
        drop(held);
        assert!(Waiting::take().is_some());
    }

    #[test]
    fn no_notice_while_notifications_are_off() {
        claims::partial(&["FR-20.7"]);
        let mut n = Notifier::default();
        assert_eq!(n.observe(4, false), None);
        // Turning them on later does not announce the four old approvals.
        assert_eq!(n.observe(4, true), None);
        assert!(n.observe(5, true).is_some());
    }

    #[test]
    fn the_text_is_fixed_except_for_the_count() {
        claims::partial(&["FR-20.7", "SR-2.6-2"]);
        for count in [2u64, 7, 12345] {
            let fixed = notice(count).body.replace(&count.to_string(), "N");
            assert_eq!(
                fixed,
                "N tool calls are waiting for approval. Open the console to review them."
            );
            assert_eq!(notice(count).title, TITLE);
        }
    }
}
