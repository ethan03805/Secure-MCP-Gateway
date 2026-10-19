//! Requirement claims of the Rust tests (SRS FR-12.10), the counterpart of
//! the Go package `internal/reqtest`.
//!
//! A test calls [`partial`] or [`verifies`] with SRS requirement IDs. The
//! claim is printed (visible with `--nocapture`) and, when the environment
//! variable `SMCP_CLAIMS_FILE` names a file, appended to it as
//! `<test name>\t<PARTIAL|VERIFIES>\t<ids>`. The test name is the libtest
//! thread name, which is the test's path. `go run ./tools/reqreport cargo`
//! joins that file with the `cargo test` output into `go test -json`
//! events, which the CI status job merges like the console's claims.

use std::fs::OpenOptions;
use std::io::Write;
use std::sync::Mutex;

fn record(kind: &str, ids: &[&str]) {
    assert!(!ids.is_empty(), "a claim names at least one requirement");
    for id in ids {
        assert!(
            id.starts_with("FR-") || id.starts_with("SR-"),
            "{id} is not an SRS requirement ID"
        );
    }
    let test = std::thread::current().name().unwrap_or("unknown").to_string();
    let line = format!("{test}\t{kind}\t{}", ids.join(" "));
    println!("{kind}: {}", ids.join(" "));
    if let Ok(path) = std::env::var("SMCP_CLAIMS_FILE") {
        // Tests run in parallel: one lock and one write per line keep
        // lines whole.
        static LOCK: Mutex<()> = Mutex::new(());
        let _guard = LOCK.lock().unwrap_or_else(|e| e.into_inner());
        if let Ok(mut f) = OpenOptions::new().create(true).append(true).open(path) {
            let _ = f.write_all(format!("{line}\n").as_bytes());
        }
    }
}

/// Claims that the calling test partly verifies each requirement.
pub fn partial(ids: &[&str]) {
    record("PARTIAL", ids);
}

/// Claims that the calling test fully verifies each requirement.
#[allow(dead_code)]
pub fn verifies(ids: &[&str]) {
    record("VERIFIES", ids);
}
