//! The code signature of a Unix socket's peer (INT-01.7, D-INT01-8): the
//! peer's audit token from the kernel (`LOCAL_PEERTOKEN`), the running code
//! it names (`SecCodeCopyGuestWithAttributes`), and macOS's own check of
//! that code against a code requirement (`SecCodeCheckValidity`). Linked
//! from the Security framework, no crate, as `trust.rs`. The audit token,
//! not the process id, names the peer, so a process id that is reused after
//! the peer quits cannot pass for it (Apple's advice for peer checks).

use std::ffi::c_void;
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;
use std::ptr::{self, NonNull};

type CfIndex = isize;

/// `kCFStringEncodingUTF8`.
const UTF8: u32 = 0x0800_0100;
/// `audit_token_t`: eight 32-bit words.
const TOKEN: usize = 8;

/// `CFDictionaryKeyCallBacks`; App only passes the address of the system's own.
#[repr(C)]
struct KeyCallBacks {
    version: CfIndex,
    retain: *const c_void,
    release: *const c_void,
    copy_description: *const c_void,
    equal: *const c_void,
    hash: *const c_void,
}

/// `CFDictionaryValueCallBacks`; only the system's own is passed.
#[repr(C)]
struct ValueCallBacks {
    version: CfIndex,
    retain: *const c_void,
    release: *const c_void,
    copy_description: *const c_void,
    equal: *const c_void,
}

#[link(name = "CoreFoundation", kind = "framework")]
unsafe extern "C" {
    static kCFTypeDictionaryKeyCallBacks: KeyCallBacks;
    static kCFTypeDictionaryValueCallBacks: ValueCallBacks;
    fn CFDataCreate(alloc: *const c_void, bytes: *const u8, len: CfIndex) -> *const c_void;
    fn CFStringCreateWithBytes(
        alloc: *const c_void,
        bytes: *const u8,
        len: CfIndex,
        encoding: u32,
        external: u8,
    ) -> *const c_void;
    fn CFDictionaryCreate(
        alloc: *const c_void,
        keys: *const *const c_void,
        values: *const *const c_void,
        count: CfIndex,
        key_callbacks: *const KeyCallBacks,
        value_callbacks: *const ValueCallBacks,
    ) -> *const c_void;
    fn CFRelease(object: *const c_void);
}

#[link(name = "Security", kind = "framework")]
unsafe extern "C" {
    static kSecGuestAttributeAudit: *const c_void;
    fn SecCodeCopyGuestWithAttributes(
        host: *const c_void,
        attributes: *const c_void,
        flags: u32,
        guest: *mut *const c_void,
    ) -> i32;
    fn SecRequirementCreateWithString(
        text: *const c_void,
        flags: u32,
        requirement: *mut *const c_void,
    ) -> i32;
    fn SecCodeCheckValidity(code: *const c_void, flags: u32, requirement: *const c_void) -> i32;
}

/// A Core Foundation object App owns (from a Create or Copy call);
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
        // SAFETY: App owns this reference (Create or Copy rule) and drops it once.
        unsafe { CFRelease(self.ptr()) }
    }
}

/// True only when the process at the other end of `stream` is validly
/// signed code that meets `requirement` (Apple's code requirement
/// language). Anything that cannot be read or checked (no audit token, no
/// such running code, a requirement that does not parse) is false.
#[must_use]
pub fn peer_meets(stream: &UnixStream, requirement: &str) -> bool {
    let Some(token) = peer_token(stream) else {
        return false;
    };
    let Some(code) = guest(&token) else {
        return false;
    };
    let Some(requirement) = parse_requirement(requirement) else {
        return false;
    };
    // SAFETY: both are live objects App owns; flags 0 is kSecCSDefaultFlags.
    unsafe { SecCodeCheckValidity(code.ptr(), 0, requirement.ptr()) == 0 }
}

/// The peer's audit token, as the kernel recorded it at connect.
fn peer_token(stream: &UnixStream) -> Option<[u32; TOKEN]> {
    let mut token = [0u32; TOKEN];
    let mut len = libc::socklen_t::try_from(size_of_val(&token)).ok()?;
    // SAFETY: the descriptor stays open while `stream` is borrowed; `token`
    // is valid for writes of `len` bytes and `len` for one write.
    let rc = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_LOCAL,
            libc::LOCAL_PEERTOKEN,
            token.as_mut_ptr().cast(),
            &mut len,
        )
    };
    (rc == 0 && usize::try_from(len).ok() == Some(size_of_val(&token))).then_some(token)
}

/// The running code the audit token names (the kernel is the host).
fn guest(token: &[u32; TOKEN]) -> Option<Cf> {
    let bytes: Vec<u8> = token.iter().flat_map(|w| w.to_ne_bytes()).collect();
    let len = CfIndex::try_from(bytes.len()).ok()?;
    // SAFETY: `bytes` is valid for `len` bytes, which CFDataCreate copies.
    let data = Cf::new(unsafe { CFDataCreate(ptr::null(), bytes.as_ptr(), len) })?;
    // SAFETY: the key is the Security framework's constant string.
    let keys = [unsafe { kSecGuestAttributeAudit }];
    let values = [data.ptr()];
    // SAFETY: one key and one value, both live; the callbacks are the
    // system's own, so the dictionary retains them for its lifetime.
    let attributes = Cf::new(unsafe {
        CFDictionaryCreate(
            ptr::null(),
            keys.as_ptr(),
            values.as_ptr(),
            1,
            &raw const kCFTypeDictionaryKeyCallBacks,
            &raw const kCFTypeDictionaryValueCallBacks,
        )
    })?;
    let mut code = ptr::null();
    // SAFETY: a null host is the kernel (Apple docs); `attributes` is live
    // and `code` is valid for one write; App owns what is written there.
    let status =
        unsafe { SecCodeCopyGuestWithAttributes(ptr::null(), attributes.ptr(), 0, &mut code) };
    let code = Cf::new(code);
    if status == 0 { code } else { None }
}

fn parse_requirement(text: &str) -> Option<Cf> {
    let len = CfIndex::try_from(text.len()).ok()?;
    // SAFETY: `text` is valid for `len` bytes, which the call copies
    // (`external` 0: not kept).
    let text =
        Cf::new(unsafe { CFStringCreateWithBytes(ptr::null(), text.as_ptr(), len, UTF8, 0) })?;
    let mut requirement = ptr::null();
    // SAFETY: `text` is live; `requirement` is valid for one write, and App
    // owns what is written there.
    let status = unsafe { SecRequirementCreateWithString(text.ptr(), 0, &mut requirement) };
    let requirement = Cf::new(requirement);
    if status == 0 { requirement } else { None }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The peer of a socket pair is this test process: linker-signed ad
    /// hoc code, valid, with no team. "always" and "never" are the
    /// requirement language's two constants.
    #[test]
    fn int01_7_peer_code_is_found_by_its_audit_token_and_checked() {
        let (a, _b) = UnixStream::pair().unwrap();
        assert!(peer_token(&a).is_some(), "no audit token");
        assert!(
            peer_meets(&a, "always"),
            "this process's code was not found or not valid"
        );
        assert!(!peer_meets(&a, "never"));
    }

    /// INT-01.7: an ad hoc build (no team) never meets a team requirement,
    /// and a requirement that does not parse never passes.
    #[test]
    fn int01_7_unsigned_peer_fails_a_team_requirement() {
        let (a, _b) = UnixStream::pair().unwrap();
        let team = r#"anchor apple generic and certificate leaf[subject.OU] = "ABCDE12345""#;
        assert!(!peer_meets(&a, team));
        assert!(!peer_meets(&a, "this is not a requirement ("));
    }
}
