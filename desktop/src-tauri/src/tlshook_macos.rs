//! SR-2.8-5 on macOS: the WKWebView server-trust challenge.
//!
//! wry's navigation delegate does not answer authentication challenges, so
//! WebKit would apply the system trust store. This module adds
//! `webView:didReceiveAuthenticationChallenge:completionHandler:` to the
//! delegate's class. For a server-trust challenge from the admin
//! listener's host and port it verifies the presented chain with
//! [`crate::tlspin::verify_chain`] (the Gateway CA bundle as the only
//! anchor, the configured host as the name) and answers with a credential
//! for that trust only on success; every other server-trust challenge, and
//! every failure, is cancelled, and the refusal callback shows the bundled
//! error page. Other challenge kinds get WebKit's default handling.

use std::ffi::c_void;
use std::ptr::NonNull;
use std::sync::{Mutex, OnceLock};

use block2::Block;
use objc2::runtime::{AnyClass, AnyObject, Imp, Sel};
use objc2::{class, ffi, msg_send, sel};
use objc2_foundation::{
    NSInteger, NSString, NSURLAuthenticationChallenge, NSURLAuthenticationMethodServerTrust, NSURLProtectionSpace,
};
use objc2_security::SecTrust;
use rustls_pki_types::CertificateDer;

use crate::tlspin;

/// The listener the console window may trust, and its anchors.
#[derive(Clone)]
pub struct Pin {
    pub host: String,
    pub port: u16,
    pub anchors: Result<Vec<CertificateDer<'static>>, tlspin::PinError>,
}

static PIN: Mutex<Option<Pin>> = Mutex::new(None);
type Refused = Box<dyn Fn(String) + Send + Sync>;
static ON_REFUSED: OnceLock<Refused> = OnceLock::new();

/// Sets the listener and anchors the handler checks against.
pub fn set_pin(p: Pin) {
    *PIN.lock().unwrap_or_else(|e| e.into_inner()) = Some(p);
}

/// Sets the callback that shows the error page after a refusal.
pub fn on_refused(f: impl Fn(String) + Send + Sync + 'static) {
    let _ = ON_REFUSED.set(Box::new(f));
}

// NSURLSessionAuthChallengeDisposition
const USE_CREDENTIAL: NSInteger = 0;
const PERFORM_DEFAULT_HANDLING: NSInteger = 1;
const CANCEL: NSInteger = 2;

type Handler = Block<dyn Fn(NSInteger, *mut AnyObject)>;

fn chain_of(trust: &SecTrust) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    // SAFETY: the array holds SecCertificate objects (SecTrustCopyCertificateChain).
    unsafe {
        if let Some(arr) = trust.certificate_chain() {
            for i in 0..arr.count() {
                let cert = arr.value_at_index(i) as *const objc2_security::SecCertificate;
                if let Some(cert) = cert.as_ref() {
                    out.push(cert.data().to_vec());
                }
            }
        }
    }
    out
}

fn refuse(reason: String) {
    if let Some(f) = ON_REFUSED.get() {
        f(reason);
    }
}

unsafe extern "C-unwind" fn did_receive_challenge(
    _this: *mut AnyObject,
    _cmd: Sel,
    _webview: *mut AnyObject,
    challenge: *mut NSURLAuthenticationChallenge,
    handler: *mut Handler,
) {
    let Some(handler) = handler.as_ref() else { return };
    let Some(challenge) = challenge.as_ref() else {
        handler.call((CANCEL, std::ptr::null_mut()));
        return;
    };
    let space: objc2::rc::Retained<NSURLProtectionSpace> = challenge.protectionSpace();
    let method: objc2::rc::Retained<NSString> = space.authenticationMethod();
    if !method.isEqualToString(NSURLAuthenticationMethodServerTrust) {
        handler.call((PERFORM_DEFAULT_HANDLING, std::ptr::null_mut()));
        return;
    }
    let host = space.host().to_string();
    let port = space.port();
    let pin = PIN.lock().unwrap_or_else(|e| e.into_inner()).clone();
    let Some(pin) = pin else {
        handler.call((CANCEL, std::ptr::null_mut()));
        return;
    };
    if !host.eq_ignore_ascii_case(&pin.host) || port != pin.port as NSInteger {
        // Not the admin listener: the console window trusts nothing else.
        handler.call((CANCEL, std::ptr::null_mut()));
        return;
    }
    let trust: *mut SecTrust = msg_send![&*space, serverTrust];
    let Some(trust_ref) = trust.as_ref() else {
        handler.call((CANCEL, std::ptr::null_mut()));
        refuse("the admin listener presented no certificate".into());
        return;
    };
    let verdict = match &pin.anchors {
        Ok(anchors) => tlspin::verify_chain(&chain_of(trust_ref), anchors, &pin.host, tlspin::now_unix()),
        Err(e) => Err(e.clone()),
    };
    match verdict {
        Ok(()) => {
            let cred: *mut AnyObject = msg_send![class!(NSURLCredential), credentialForTrust: trust];
            handler.call((USE_CREDENTIAL, cred));
        }
        Err(e) => {
            handler.call((CANCEL, std::ptr::null_mut()));
            refuse(e.to_string());
        }
    }
}

/// Adds the challenge handler to the class of the web view's navigation
/// delegate. Idempotent; fails if the class already has a handler that is
/// not this one (a wry upgrade that adds its own must be reviewed).
///
/// # Safety
/// `wkwebview` must be a live `WKWebView` pointer, on the main thread.
pub unsafe fn install(wkwebview: *mut c_void) -> Result<(), String> {
    let wv = NonNull::new(wkwebview as *mut AnyObject).ok_or("no web view")?;
    let delegate: *mut AnyObject = msg_send![wv.as_ptr(), navigationDelegate];
    if delegate.is_null() {
        return Err("the web view has no navigation delegate".into());
    }
    let cls = ffi::object_getClass(delegate) as *mut AnyClass;
    let name = sel!(webView:didReceiveAuthenticationChallenge:completionHandler:);
    let ours: Imp = std::mem::transmute::<
        unsafe extern "C-unwind" fn(
            *mut AnyObject,
            Sel,
            *mut AnyObject,
            *mut NSURLAuthenticationChallenge,
            *mut Handler,
        ),
        Imp,
    >(did_receive_challenge);
    if !ffi::class_addMethod(cls, name, ours, c"v@:@@@?".as_ptr()).as_bool() {
        let m = ffi::class_getInstanceMethod(cls, name);
        match ffi::method_getImplementation(m) {
            Some(imp) if imp as usize == ours as usize => {}
            _ => return Err("the navigation delegate already answers authentication challenges".into()),
        }
    }
    // WebKit records which delegate methods exist when the delegate is
    // set; setting it again makes it see the new one.
    let _: () = msg_send![wv.as_ptr(), setNavigationDelegate: delegate];
    let responds: bool = msg_send![delegate, respondsToSelector: name];
    if responds {
        Ok(())
    } else {
        Err("the challenge handler was not installed".into())
    }
}
