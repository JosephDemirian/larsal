//! macOS's own trust evaluation of a TLS server's certificates, for the
//! HTTPS client (`net`, LD-247 (2)), linked from the Security framework (no
//! crate). The OS decides trust: the chain up to a root this Mac trusts, the
//! host name, the dates, the key purposes and revocation, as
//! `SecPolicyCreateSSL` defines them for a server. Larsal writes no crypto here
//! (AGENTS.md rule 3); the handshake signatures stay rustls's own checks.
//!
//! Tests give their own root as the only anchor of the trust object
//! (`SecTrustSetAnchorCertificates`): no keychain is read or changed.

use std::ffi::{CStr, c_char, c_void};
use std::ptr::{self, NonNull};

type CfIndex = isize;

/// `kCFStringEncodingUTF8`.
const UTF8: u32 = 0x0800_0100;

/// `CFArrayCallBacks`; Larsal only passes the address of the system's own.
#[repr(C)]
struct ArrayCallBacks {
    version: CfIndex,
    retain: *const c_void,
    release: *const c_void,
    copy_description: *const c_void,
    equal: *const c_void,
}

#[link(name = "CoreFoundation", kind = "framework")]
unsafe extern "C" {
    static kCFTypeArrayCallBacks: ArrayCallBacks;
    fn CFDataCreate(alloc: *const c_void, bytes: *const u8, len: CfIndex) -> *const c_void;
    fn CFArrayCreate(
        alloc: *const c_void,
        values: *const *const c_void,
        count: CfIndex,
        callbacks: *const ArrayCallBacks,
    ) -> *const c_void;
    fn CFStringCreateWithBytes(
        alloc: *const c_void,
        bytes: *const u8,
        len: CfIndex,
        encoding: u32,
        external: u8,
    ) -> *const c_void;
    fn CFStringGetCString(
        string: *const c_void,
        buffer: *mut c_char,
        size: CfIndex,
        encoding: u32,
    ) -> u8;
    fn CFErrorGetCode(error: *const c_void) -> CfIndex;
    fn CFErrorCopyDescription(error: *const c_void) -> *const c_void;
    fn CFRelease(object: *const c_void);
}

#[link(name = "Security", kind = "framework")]
unsafe extern "C" {
    fn SecCertificateCreateWithData(alloc: *const c_void, data: *const c_void) -> *const c_void;
    fn SecPolicyCreateSSL(server: u8, host: *const c_void) -> *const c_void;
    fn SecTrustCreateWithCertificates(
        certificates: *const c_void,
        policies: *const c_void,
        trust: *mut *const c_void,
    ) -> i32;
    fn SecTrustSetAnchorCertificates(trust: *const c_void, anchors: *const c_void) -> i32;
    fn SecTrustSetOCSPResponse(trust: *const c_void, response: *const c_void) -> i32;
    fn SecTrustEvaluateWithError(trust: *const c_void, error: *mut *const c_void) -> bool;
}

/// A Core Foundation object Larsal owns (from a Create or Copy call);
/// released when dropped.
struct Cf(NonNull<c_void>);

impl Cf {
    fn new(raw: *const c_void) -> Option<Self> {
        NonNull::new(raw.cast_mut()).map(Self)
    }

    fn ptr(&self) -> *const c_void {
        self.0.as_ptr()
    }
}

impl Drop for Cf {
    fn drop(&mut self) {
        // SAFETY: the pointer came from a Create or Copy call, so Larsal holds
        // one reference, and this is its only release.
        unsafe { CFRelease(self.0.as_ptr()) }
    }
}

/// Why a chain was not trusted.
#[derive(Debug)]
pub enum Refused {
    /// A certificate is not DER that macOS can read.
    BadEncoding,
    /// macOS's answer: a Security framework `OSStatus` (`SecBase.h`, for
    /// example -67818 `errSecCertificateExpired`) and macOS's own text. Code
    /// 0 when macOS could not make the trust object at all.
    Os {
        /// The `OSStatus`.
        code: i64,
        /// macOS's description of it.
        text: String,
    },
}

fn setup_failed() -> Refused {
    Refused::Os {
        code: 0,
        text: "macOS could not start the trust evaluation".into(),
    }
}

fn status(code: i32) -> Result<(), Refused> {
    match code {
        0 => Ok(()),
        code => Err(Refused::Os {
            code: code.into(),
            text: format!("macOS refused the trust settings ({code})"),
        }),
    }
}

fn data(bytes: &[u8]) -> Option<Cf> {
    let len = CfIndex::try_from(bytes.len()).ok()?;
    // SAFETY: `bytes` is valid for reads of `len` bytes for the call, which
    // copies them; null is the default allocator.
    Cf::new(unsafe { CFDataCreate(ptr::null(), bytes.as_ptr(), len) })
}

fn array(items: &[Cf]) -> Option<Cf> {
    let values: Vec<*const c_void> = items.iter().map(Cf::ptr).collect();
    let len = CfIndex::try_from(values.len()).ok()?;
    // SAFETY: `values` holds `len` live CF objects for the call; the CFType
    // callbacks are the system's own and retain each object, so the array
    // keeps them alive after `items` is dropped.
    Cf::new(unsafe {
        CFArrayCreate(
            ptr::null(),
            values.as_ptr(),
            len,
            &raw const kCFTypeArrayCallBacks,
        )
    })
}

/// One CFArray of SecCertificates from DER certificates, in order.
fn certificates(ders: &[&[u8]]) -> Result<Cf, Refused> {
    let mut certs = Vec::with_capacity(ders.len());
    for der in ders {
        let data = data(der).ok_or_else(setup_failed)?;
        // SAFETY: `data` is a live CFData; the call returns a new
        // certificate, or null when the bytes are not a DER certificate.
        let cert = unsafe { SecCertificateCreateWithData(ptr::null(), data.ptr()) };
        certs.push(Cf::new(cert).ok_or(Refused::BadEncoding)?);
    }
    array(&certs).ok_or_else(setup_failed)
}

/// macOS's text for a CFError, at most 1,023 bytes; empty when it has none.
fn description(error: &Cf) -> String {
    // SAFETY: `error` is a live CFError; the call returns a new string or null.
    let Some(text) = Cf::new(unsafe { CFErrorCopyDescription(error.ptr()) }) else {
        return String::new();
    };
    let mut buffer = [0 as c_char; 1024];
    // SAFETY: `text` is a live CFString and `buffer` is valid for writes of
    // its whole length, which is the size passed; on success the call writes
    // NUL-terminated UTF-8 inside it.
    let ok = unsafe { CFStringGetCString(text.ptr(), buffer.as_mut_ptr(), 1024, UTF8) };
    if ok == 0 {
        return String::new();
    }
    // SAFETY: the call succeeded, so `buffer` holds a NUL inside its length.
    unsafe { CStr::from_ptr(buffer.as_ptr()) }
        .to_string_lossy()
        .into_owned()
}

/// Evaluates a TLS server's certificates the way macOS does for `host`.
///
/// `chain` is the server's leaf first, then the other certificates it sent
/// (DER). `ocsp` is a stapled OCSP response, or empty. `anchors`, when not
/// empty, are the only roots trusted for this one evaluation (tests); empty
/// means this Mac's own trust settings. macOS reads the clock itself.
pub fn evaluate_server(
    chain: &[&[u8]],
    host: &str,
    ocsp: &[u8],
    anchors: &[&[u8]],
) -> Result<(), Refused> {
    #[cfg(test)]
    probe::count();
    let certs = certificates(chain)?;
    let len = CfIndex::try_from(host.len()).map_err(|_| setup_failed())?;
    // SAFETY: `host` is UTF-8, valid for reads of `len` bytes for the call,
    // which copies them (`external` 0: not kept).
    let name = unsafe { CFStringCreateWithBytes(ptr::null(), host.as_ptr(), len, UTF8, 0) };
    let name = Cf::new(name).ok_or_else(setup_failed)?;
    // SAFETY: `name` is a live CFString; 1 asks for the server side of TLS.
    // The call returns a new policy or null.
    let policy = Cf::new(unsafe { SecPolicyCreateSSL(1, name.ptr()) }).ok_or_else(setup_failed)?;
    let policies = array(std::slice::from_ref(&policy)).ok_or_else(setup_failed)?;
    let mut raw = ptr::null();
    // SAFETY: both arrays are live for the call; `raw` is valid for one
    // write, and on success holds a new trust object Larsal owns.
    status(unsafe { SecTrustCreateWithCertificates(certs.ptr(), policies.ptr(), &raw mut raw) })?;
    let trust = Cf::new(raw).ok_or_else(setup_failed)?;
    if !anchors.is_empty() {
        let anchors = certificates(anchors)?;
        // SAFETY: both objects are live; the trust object retains the array.
        // With anchors set, macOS trusts only these roots for this object.
        status(unsafe { SecTrustSetAnchorCertificates(trust.ptr(), anchors.ptr()) })?;
    }
    if !ocsp.is_empty() {
        let response = data(ocsp).ok_or_else(setup_failed)?;
        // SAFETY: both objects are live; the trust object retains the data.
        status(unsafe { SecTrustSetOCSPResponse(trust.ptr(), response.ptr()) })?;
    }
    let mut error = ptr::null();
    // SAFETY: `trust` is live; `error` is valid for one write, and on
    // failure may hold a new CFError Larsal owns.
    if unsafe { SecTrustEvaluateWithError(trust.ptr(), &raw mut error) } {
        return Ok(());
    }
    let Some(error) = Cf::new(error) else {
        return Err(Refused::Os {
            code: 0,
            text: "macOS did not trust the certificate".into(),
        });
    };
    // SAFETY: `error` is a live CFError.
    let code = i64::try_from(unsafe { CFErrorGetCode(error.ptr()) }).unwrap_or_default();
    let mut text = description(&error);
    if text.is_empty() {
        text = format!("macOS refused it (error {code})");
    }
    Err(Refused::Os { code, text })
}

/// Tests only: how many trust evaluations this thread asked macOS for, so a
/// test can see that the pinned path never asks it (LD-317 (3)). The
/// verifier runs on the thread that makes the request.
#[cfg(test)]
pub(crate) mod probe {
    use std::cell::Cell;

    thread_local! {
        static CALLS: Cell<usize> = const { Cell::new(0) };
    }

    pub(super) fn count() {
        CALLS.with(|n| n.set(n.get().wrapping_add(1)));
    }

    /// Evaluations on this thread since the last `take`.
    pub(crate) fn take() -> usize {
        CALLS.with(Cell::take)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn not_der_is_bad_encoding() {
        let refused = evaluate_server(&[b"not a certificate"], "127.0.0.1", &[], &[]);
        assert!(matches!(refused, Err(Refused::BadEncoding)), "{refused:?}");
    }
}
