//! System facts for `--debug-info` (APP-09.4), the KDF cost check
//! (CRY-02.14), the KDF benchmark's clock (LD-72) and local times
//! (INT-10.31).

#[cfg(feature = "appkit")]
use objc2_foundation::NSProcessInfo;
use std::ffi::CStr;
use std::io;
use std::mem::MaybeUninit;
use std::time::Duration;

/// The kernel name and release, for example `("Darwin", "25.0.0")`.
pub fn kernel() -> io::Result<(String, String)> {
    let name = uname()?;
    Ok((text(&name.sysname), text(&name.release)))
}

/// This Mac's host name as `hostname` and `uname -n` print it (often ending
/// in `.local`): the name auto-open's device rule compares (APP-06.25).
/// Empty when it cannot be read.
#[must_use]
pub fn host_name() -> String {
    uname().map(|n| text(&n.nodename)).unwrap_or_default()
}

fn uname() -> io::Result<libc::utsname> {
    // Zeroed, not uninit: uname writes each field only up to its NUL, so the
    // bytes after it would stay unwritten (Checker 2, 2026-10-27).
    let mut name = MaybeUninit::<libc::utsname>::zeroed();
    // SAFETY: `name` is valid for writes of a utsname and every byte starts at
    // zero, so it is a valid utsname whatever uname writes. assume_init runs
    // only after uname returned 0, which means each field holds NUL-terminated
    // text.
    unsafe {
        if libc::uname(name.as_mut_ptr()) != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(name.assume_init())
    }
}

fn text(field: &[libc::c_char]) -> String {
    let bytes: Vec<u8> = field.iter().map(|&c| c as u8).collect();
    CStr::from_bytes_until_nul(&bytes)
        .map(|c| c.to_string_lossy().into_owned())
        .unwrap_or_default()
}

/// The macOS version, for example `26.0.1`.
#[cfg(feature = "appkit")]
#[must_use]
pub fn os_version() -> String {
    let v = NSProcessInfo::processInfo().operatingSystemVersion();
    format!("{}.{}.{}", v.majorVersion, v.minorVersion, v.patchVersion)
}

/// This Mac's physical memory in bytes, for the KDF cost check (CRY-02.14).
#[cfg(feature = "appkit")]
#[must_use]
pub fn physical_memory() -> u64 {
    NSProcessInfo::processInfo().physicalMemory()
}

/// This thread's CPU time: the KDF benchmark's clock (LD-72, CRY-02.28).
/// Time the thread waits while other work runs does not count, so a busy
/// Mac cannot make the tuned KDF weaker (AT-B06). The KDF runs on the
/// calling thread only (argon2 without its parallel feature).
///
/// # Panics
/// When macOS cannot read the clock, which happens only for an unknown clock
/// id; this one exists on every macOS App runs on. A clock that stood still
/// would tune the maximum count, and one that guessed would tune a weaker
/// KDF, so the app ends instead (LD-156 (9)).
#[must_use]
pub fn thread_cpu_time() -> Duration {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: `ts` is a valid, initialised timespec that lives across the
    // call; clock_gettime only writes into it and reads nothing else.
    let done = unsafe { libc::clock_gettime(libc::CLOCK_THREAD_CPUTIME_ID, &mut ts) };
    assert_eq!(done, 0, "the thread CPU-time clock failed");
    // Both fields are never negative for a CPU time; nanoseconds < 10^9.
    Duration::new(
        u64::try_from(ts.tv_sec).unwrap_or(0),
        u32::try_from(ts.tv_nsec).unwrap_or(0),
    )
}

/// The local time's offset from UTC in seconds at Unix time `t`, by
/// macOS's own zone rules: they follow `TZ`, and a zone's rule string covers
/// the years after its stored changes (LD-178). `None` when macOS cannot
/// convert `t`.
#[must_use]
pub fn utc_offset(t: i64) -> Option<i64> {
    let t: libc::time_t = t;
    let mut tm = libc::tm::default();
    // SAFETY: `t` and `tm` are valid for the call and live across it;
    // localtime_r writes only into `tm` and returns null when it fails.
    let done = unsafe { libc::localtime_r(&t, &mut tm) };
    (!done.is_null()).then_some(tm.tm_gmtoff)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Run by `utc_offset_follows_tz_and_later_rules` with `TZ` set.
    #[test]
    #[ignore = "a child of utc_offset_follows_tz_and_later_rules"]
    fn offset_child() {
        // 2024-01-01, 2024-07-01 and 2040-07-01, each at 00:00 UTC.
        for t in [1_704_067_200, 1_719_792_000, 2_224_713_600] {
            println!("offset {}", utc_offset(t).unwrap());
        }
    }

    #[test]
    fn utc_offset_follows_tz_and_later_rules() {
        let me = std::env::current_exe().unwrap();
        for (tz, want) in [
            ("Europe/Berlin", [3600, 7200, 7200]),
            ("America/New_York", [-18_000, -14_400, -14_400]),
            ("UTC", [0, 0, 0]),
        ] {
            let out = std::process::Command::new(&me)
                .args([
                    "--exact",
                    "macos::system::tests::offset_child",
                    "--ignored",
                    "--nocapture",
                ])
                .env("TZ", tz)
                .output()
                .unwrap();
            let text = String::from_utf8_lossy(&out.stdout);
            let got: Vec<i64> = text
                .lines()
                .filter_map(|l| l.strip_prefix("offset "))
                .map(|n| n.parse().unwrap())
                .collect();
            assert_eq!(got, want, "{tz}: {text}");
        }
    }

    /// LD-72: the clock counts this thread's work, never its waiting.
    #[test]
    fn thread_cpu_time_stands_still_while_the_thread_sleeps() {
        let before = thread_cpu_time();
        std::thread::sleep(Duration::from_millis(300));
        let slept = thread_cpu_time().saturating_sub(before);
        assert!(slept < Duration::from_millis(50), "{slept:?}");
        // Work moves it (bounded by 5 s of wall time on a very busy Mac).
        let start = std::time::Instant::now();
        let worked = || thread_cpu_time().saturating_sub(before);
        while worked() < Duration::from_millis(20) && start.elapsed() < Duration::from_secs(5) {}
        assert!(worked() >= Duration::from_millis(20));
    }

    #[test]
    #[cfg(feature = "appkit")]
    fn kernel_and_os_version_are_filled() {
        let (name, release) = kernel().unwrap();
        assert_eq!(name, "Darwin");
        assert!(
            release.chars().next().unwrap().is_ascii_digit(),
            "{release}"
        );
        assert!(os_version().split('.').count() == 3);
        assert!(physical_memory() >= 1 << 30);
    }
}
