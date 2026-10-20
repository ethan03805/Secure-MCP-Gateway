//! SR-2.8-5 on Windows: the WebView2 certificate hook.
//!
//! The decisions are in [`crate::tlswebview2`]; this module connects them
//! to the console window's WebView2:
//!
//! - `ServerCertificateErrorDetected` (ICoreWebView2_14): the presented
//!   chain (`ServerCertificate`, `PemEncodedIssuerCertificateChain`) is
//!   checked against the Gateway CA; the answer is `ALWAYS_ALLOW` for the
//!   admin listener's certificate and `CANCEL` for everything else, and a
//!   cancel shows the error page;
//! - `NavigationCompleted`: for every https page the window shows, the
//!   DevTools protocol's `Network.getCertificate` for the admin origin
//!   gives the certificate chain the page was loaded with, which must chain
//!   to the Gateway CA too, so a certificate Windows trusts is not accepted
//!   on that ground alone. A failure stops the page and shows the error
//!   page.
//!
//! A WebView2 runtime without ICoreWebView2_14 (older than 1.0.1245) cannot
//! be checked and is refused.

use webview2_com::Microsoft::Web::WebView2::Win32::{
    ICoreWebView2, ICoreWebView2Controller, ICoreWebView2ServerCertificateErrorDetectedEventArgs, ICoreWebView2_14,
    COREWEBVIEW2_SERVER_CERTIFICATE_ERROR_ACTION_ALWAYS_ALLOW, COREWEBVIEW2_SERVER_CERTIFICATE_ERROR_ACTION_CANCEL,
};
use webview2_com::{
    take_pwstr, CallDevToolsProtocolMethodCompletedHandler, NavigationCompletedEventHandler,
    ServerCertificateErrorDetectedEventHandler,
};
use windows::core::{w, Interface, HSTRING, PWSTR};

use crate::tlspin;
use crate::tlswebview2::{self, Pin, Verdict};

fn chain_of(args: &ICoreWebView2ServerCertificateErrorDetectedEventArgs) -> Result<Vec<Vec<u8>>, String> {
    // SAFETY: COM calls on a live event argument, on the UI thread.
    unsafe {
        let cert = args.ServerCertificate().map_err(|e| e.to_string())?;
        let mut pem = PWSTR::null();
        cert.ToPemEncoding(&mut pem).map_err(|e| e.to_string())?;
        let leaf = take_pwstr(pem);
        let mut issuers = Vec::new();
        if let Ok(list) = cert.PemEncodedIssuerCertificateChain() {
            let mut n = 0u32;
            list.Count(&mut n).map_err(|e| e.to_string())?;
            for i in 0..n.min(8) {
                let mut s = PWSTR::null();
                list.GetValueAtIndex(i, &mut s).map_err(|e| e.to_string())?;
                issuers.push(take_pwstr(s));
            }
        }
        tlswebview2::chain_from_pem(&leaf, &issuers)
    }
}

fn source(wv: &ICoreWebView2) -> String {
    let mut s = PWSTR::null();
    // SAFETY: COM call on a live web view, on the UI thread.
    unsafe {
        if wv.Source(&mut s).is_err() {
            return String::new();
        }
    }
    take_pwstr(s)
}

/// Connects the handlers and then loads `target`. `refused` shows the
/// error page; `accepted` is called after a committed page passed the
/// check.
pub fn install(
    controller: &ICoreWebView2Controller,
    pin: Pin,
    refused: impl Fn(String) + Clone + 'static,
    accepted: impl Fn() + Clone + 'static,
    target: &str,
) -> Result<(), String> {
    // SAFETY: COM calls on the window's live controller, on the UI thread
    // (Tauri runs with_webview there).
    unsafe {
        let wv = controller.CoreWebView2().map_err(|e| e.to_string())?;
        let wv14: ICoreWebView2_14 = wv
            .cast()
            .map_err(|_| "the WebView2 runtime is too old to check the certificate (update Microsoft Edge WebView2)")?;
        let mut token = 0i64;
        let (p1, r1) = (pin.clone(), refused.clone());
        wv14.add_ServerCertificateErrorDetected(
            &ServerCertificateErrorDetectedEventHandler::create(Box::new(move |_, args| {
                let Some(args) = args else { return Ok(()) };
                let mut uri = PWSTR::null();
                args.RequestUri(&mut uri)?;
                let uri = take_pwstr(uri);
                match tlswebview2::on_certificate_error(&p1, &uri, chain_of(&args), tlspin::now_unix()) {
                    Verdict::Allow => args.SetAction(COREWEBVIEW2_SERVER_CERTIFICATE_ERROR_ACTION_ALWAYS_ALLOW)?,
                    Verdict::Cancel(reason) => {
                        args.SetAction(COREWEBVIEW2_SERVER_CERTIFICATE_ERROR_ACTION_CANCEL)?;
                        r1(reason);
                    }
                }
                Ok(())
            })),
            &mut token,
        )
        .map_err(|e| e.to_string())?;
        wv.add_NavigationCompleted(
            &NavigationCompletedEventHandler::create(Box::new(move |wv, _| {
                let Some(wv) = wv else { return Ok(()) };
                let page = source(&wv);
                if !tlswebview2::needs_check(&page) {
                    return Ok(());
                }
                let (p2, r2, a2, r3) = (pin.clone(), refused.clone(), accepted.clone(), refused.clone());
                let wv2 = wv.clone();
                let params = HSTRING::from(tlswebview2::get_certificate_params(&pin));
                let called = wv.CallDevToolsProtocolMethod(
                    w!("Network.getCertificate"),
                    &params,
                    &CallDevToolsProtocolMethodCompletedHandler::create(Box::new(move |hr, json| {
                        let answer = hr.map(|()| json).map_err(|e| format!("Network.getCertificate: {e}"));
                        match tlswebview2::on_committed(
                            &p2,
                            &page,
                            answer.as_deref().map_err(Clone::clone),
                            tlspin::now_unix(),
                        ) {
                            Ok(()) => a2(),
                            Err(e) => {
                                let _ = wv2.Stop();
                                r2(e);
                            }
                        }
                        Ok(())
                    })),
                );
                if let Err(e) = called {
                    let _ = wv.Stop();
                    r3(format!("Network.getCertificate: {e}"));
                }
                Ok(())
            })),
            &mut token,
        )
        .map_err(|e| e.to_string())?;
        wv14.Navigate(&HSTRING::from(target)).map_err(|e| e.to_string())?;
    }
    Ok(())
}
