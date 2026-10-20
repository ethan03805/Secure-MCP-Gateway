//! Windows process helpers (FR-20.3, SR-2-7): a command run with the User
//! Account Control prompt for the machine-mode service, and the system's
//! text for a Win32 error code.
//!
//! The elevated command is started with `ShellExecuteExW` and the verb
//! `runas`, which shows the consent prompt with the program's path; the
//! program is a fixed absolute path and its arguments are quoted by the
//! Microsoft C runtime rules ([`crate::service::windows_command_line`]),
//! with no shell. An elevated process's output cannot be read by the
//! unelevated application, so the result is its exit code; `smcpctl
//! service` puts a Win32 error code there (with the customer-code bit),
//! whose text [`win32_message`] gives.

use std::time::Duration;

use windows::core::{HSTRING, PCWSTR, PWSTR};
use windows::Win32::Foundation::{CloseHandle, ERROR_CANCELLED, WAIT_OBJECT_0, WAIT_TIMEOUT};
use windows::Win32::System::Diagnostics::Debug::{
    FormatMessageW, FORMAT_MESSAGE_FROM_SYSTEM, FORMAT_MESSAGE_IGNORE_INSERTS,
};
use windows::Win32::System::Threading::{GetExitCodeProcess, WaitForSingleObject};
use windows::Win32::UI::Shell::{
    ShellExecuteExW, SEE_MASK_FLAG_NO_UI, SEE_MASK_NOASYNC, SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW,
};
use windows::Win32::UI::WindowsAndMessaging::SW_HIDE;

use crate::service::{windows_command_line, RunResult};

/// The system's text for a Win32 error code, without the trailing line
/// break; None when the system has none.
pub fn win32_message(code: u32) -> Option<String> {
    let mut buf = [0u16; 512];
    // SAFETY: the buffer and its length are valid; no inserts are read.
    let n = unsafe {
        FormatMessageW(
            FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
            None,
            code,
            0,
            PWSTR(buf.as_mut_ptr()),
            buf.len() as u32,
            None,
        )
    };
    if n == 0 {
        return None;
    }
    let s = String::from_utf16_lossy(&buf[..n as usize]).trim().to_string();
    (!s.is_empty()).then_some(s)
}

/// Runs `argv` with the User Account Control prompt and waits up to
/// `timeout` for it to end. A declined prompt is reported as a spawn
/// error with the system's text.
pub fn run_elevated(argv: &[String], timeout: Duration) -> RunResult {
    let Some((prog, args)) = argv.split_first() else {
        return RunResult {
            spawn_error: Some("empty command".into()),
            ..Default::default()
        };
    };
    let file = HSTRING::from(prog.as_str());
    let params = HSTRING::from(windows_command_line(args));
    let mut info = SHELLEXECUTEINFOW {
        cbSize: std::mem::size_of::<SHELLEXECUTEINFOW>() as u32,
        fMask: SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC | SEE_MASK_FLAG_NO_UI,
        lpVerb: windows::core::w!("runas"),
        lpFile: PCWSTR(file.as_ptr()),
        lpParameters: PCWSTR(params.as_ptr()),
        nShow: SW_HIDE.0,
        ..Default::default()
    };
    // SAFETY: info points at valid strings that outlive the call.
    if let Err(e) = unsafe { ShellExecuteExW(&mut info) } {
        let declined = e.code() == ERROR_CANCELLED.to_hresult();
        return RunResult {
            spawn_error: Some(if declined {
                "the User Account Control prompt was declined".into()
            } else {
                format!("{prog}: {}", e.message())
            }),
            ..Default::default()
        };
    }
    let h = info.hProcess;
    if h.is_invalid() {
        return RunResult {
            spawn_error: Some(format!("{prog}: no process handle")),
            ..Default::default()
        };
    }
    let ms = u32::try_from(timeout.as_millis()).unwrap_or(u32::MAX);
    // SAFETY: h is the process handle ShellExecuteExW returned; closed once.
    unsafe {
        let w = WaitForSingleObject(h, ms);
        let mut res = RunResult::default();
        if w == WAIT_TIMEOUT {
            res.timed_out = true;
        } else if w == WAIT_OBJECT_0 {
            let mut code = 0u32;
            match GetExitCodeProcess(h, &mut code) {
                Ok(()) => res.code = Some(code as i32),
                Err(e) => res.spawn_error = Some(e.message()),
            }
        } else {
            res.spawn_error = Some("waiting for the elevated command failed".into());
        }
        let _ = CloseHandle(h);
        res
    }
}
