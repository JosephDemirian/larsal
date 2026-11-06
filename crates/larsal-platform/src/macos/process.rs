//! Process memory and hardening on macOS. The release-only hardening
//! switch and warning are in `hardening.rs`.

use std::io;

/// Returns this process's current resident memory in bytes.
///
/// Returns the operating system error if the memory query fails.
pub fn resident_bytes() -> io::Result<u64> {
    let mut usage = std::mem::MaybeUninit::<libc::rusage_info_v2>::zeroed();
    // SAFETY: the aligned V2 buffer is read only after the kernel fills it successfully for our PID.
    unsafe {
        if libc::proc_pid_rusage(
            libc::getpid(),
            libc::RUSAGE_INFO_V2,
            usage.as_mut_ptr().cast(),
        ) != 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(usage.assume_init().ri_resident_size)
    }
}

/// APP-11.2: sets the core file size limit, soft and hard, to 0
/// (`setrlimit(2)`). Child processes inherit it, and an unprivileged process
/// cannot raise a hard limit again.
pub fn core_dumps_off() -> io::Result<()> {
    let zero = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: `zero` is a valid rlimit that lives across the call, and
    // setrlimit only reads it.
    if unsafe { libc::setrlimit(libc::RLIMIT_CORE, &zero) } == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// APP-11.3: `ptrace(PT_DENY_ATTACH, 0, 0, 0)` (`ptrace(2)`, request 31).
/// From then on the kernel refuses ptrace attach to this process: lldb and
/// gdb fail, and the attaching process gets SIGSEGV. If this process is being
/// traced when it calls this, the kernel ends it with exit status 45
/// (ENOTSUP). Limits: root, a kernel extension, or the task port (which the
/// hardened runtime keeps from other non-root processes) get around it.
pub fn deny_debugger() -> io::Result<()> {
    // SAFETY: PT_DENY_ATTACH ignores pid, addr and data, and touches no
    // memory of ours. Its only other effect, ending a traced process, is the
    // one wanted.
    if unsafe { libc::ptrace(libc::PT_DENY_ATTACH, 0, std::ptr::null_mut(), 0) } == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader};
    use std::process::{Child, Command, Stdio};
    use std::sync::atomic::{AtomicBool, Ordering};

    /// Tells a child run of this test binary what to do.
    const ROLE: &str = "LARSAL_TEST_HARDENING_ROLE";
    const TARGET_PID: &str = "LARSAL_TEST_HARDENING_PID";

    #[test]
    fn resident_bytes_is_positive() {
        assert!(resident_bytes().unwrap() > 0);
    }

    fn core_limit() -> (u64, u64) {
        let mut now = libc::rlimit {
            rlim_cur: 7,
            rlim_max: 7,
        };
        // SAFETY: `now` is valid for writes of an rlimit.
        assert_eq!(unsafe { libc::getrlimit(libc::RLIMIT_CORE, &mut now) }, 0);
        (now.rlim_cur, now.rlim_max)
    }

    #[test]
    fn app11_2_core_limit_is_zero_and_cannot_be_raised() {
        // The child also checks that it cannot raise the limit again.
        let (limit, _) = attach_to("core");
        assert_eq!(limit, ("0".into(), "0".into()));
    }

    /// A child: applies its role's steps, prints `ready <soft> <hard>` (its
    /// core limit), then waits until its standard input closes.
    #[test]
    #[ignore = "a child of the attach tests below"]
    fn hardening_target_child() {
        match std::env::var(ROLE).as_deref() {
            Ok("deny") => deny_debugger().unwrap(),
            Ok("harden") => {
                crate::hardening::harden();
            }
            Ok("core") => {
                core_dumps_off().unwrap();
                let one = libc::rlimit {
                    rlim_cur: 1,
                    rlim_max: 1,
                };
                // SAFETY: `one` is a valid rlimit that setrlimit only reads.
                let raised = unsafe { libc::setrlimit(libc::RLIMIT_CORE, &one) };
                assert_eq!(raised, -1, "an unprivileged process raised its hard limit");
            }
            Ok("plain") => {}
            _ => return,
        }
        let (soft, hard) = core_limit();
        println!("ready {soft} {hard}");
        let _ = std::io::stdin().lines().count();
    }

    static GOT_SEGV: AtomicBool = AtomicBool::new(false);

    extern "C" fn on_segv(_: libc::c_int) {
        GOT_SEGV.store(true, Ordering::SeqCst);
    }

    /// A child: tries `ptrace(PT_ATTACHEXC)` on the target and prints
    /// `attach <return value> <errno> <SIGSEGV seen>`. The kernel answers an
    /// attach to a process that denied it with EBUSY plus SIGSEGV to the
    /// attacher; a handler records the signal so no crash report is made.
    #[test]
    #[ignore = "a child of the attach tests below"]
    fn hardening_attacher_child() {
        let Ok(pid) = std::env::var(TARGET_PID) else {
            return;
        };
        let pid: libc::pid_t = pid.parse().unwrap();
        let handler = on_segv as extern "C" fn(libc::c_int);
        // SAFETY: the handler only stores to an atomic, which is
        // async-signal-safe.
        unsafe { libc::signal(libc::SIGSEGV, handler as libc::sighandler_t) };
        // SAFETY: PT_ATTACHEXC reads no memory of ours; `pid` is the
        // target child the parent test started.
        let rc = unsafe { libc::ptrace(libc::PT_ATTACHEXC, pid, std::ptr::null_mut(), 0) };
        let errno = io::Error::last_os_error().raw_os_error().unwrap_or(0);
        // The kernel may hand the signal to another thread of this process.
        for _ in 0..50 {
            if GOT_SEGV.load(Ordering::SeqCst) {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        println!("attach {rc} {errno} {}", GOT_SEGV.load(Ordering::SeqCst));
    }

    fn child(test: &str) -> Command {
        let mut c = Command::new(std::env::current_exe().unwrap());
        c.args([
            "--exact",
            test,
            "--ignored",
            "--nocapture",
            "--test-threads=1",
        ]);
        c
    }

    /// What follows `prefix` on the first stdout line of `child` that has it, split.
    fn line(child: &mut Child, prefix: &str) -> Vec<String> {
        let out = BufReader::new(child.stdout.as_mut().unwrap());
        for l in out.lines() {
            let l = l.unwrap();
            // libtest may print the test name first on the same line.
            if let Some((_, rest)) = l.split_once(prefix) {
                return rest.split(' ').map(str::to_owned).collect();
            }
        }
        panic!("no {prefix:?} line from the child");
    }

    /// Starts a target with `role`, attaches to it from a second child, and
    /// returns the target's core limit and the attach result.
    fn attach_to(role: &str) -> ((String, String), (i32, i32, bool)) {
        let mut target = child("macos::process::tests::hardening_target_child")
            .env(ROLE, role)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let ready = line(&mut target, "ready ");
        let out = child("macos::process::tests::hardening_attacher_child")
            .env(TARGET_PID, target.id().to_string())
            .output()
            .unwrap();
        // Ends the target whatever the attach did; by its own PID (rule 11).
        let _ = target.kill();
        let _ = target.wait();
        let text = String::from_utf8_lossy(&out.stdout);
        let attach: Vec<&str> = text
            .lines()
            .find_map(|l| l.split_once("attach ").map(|(_, rest)| rest))
            .unwrap_or_else(|| panic!("attacher said: {text} {out:?}"))
            .split(' ')
            .collect();
        (
            (ready[0].clone(), ready[1].clone()),
            (
                attach[0].parse().unwrap(),
                attach[1].parse().unwrap(),
                attach[2].parse().unwrap(),
            ),
        )
    }

    #[test]
    fn app11_3_deny_attach_refuses_ptrace_attach() {
        // Control: without the call the kernel does not answer EBUSY plus
        // SIGSEGV, so that answer below comes from the deny flag alone.
        let (_, plain) = attach_to("plain");
        assert_ne!((plain.1, plain.2), (libc::EBUSY, true), "{plain:?}");
        let (_, denied) = attach_to("deny");
        assert_eq!(denied, (-1, libc::EBUSY, true));
    }

    /// APP-11.5 and AT-C03: `harden()` in a child of this test binary. Under
    /// `cargo test --release` the child is a release build: core limit 0
    /// and attach refused. Under plain `cargo test` (debug assertions on)
    /// nothing changes, so a debugger can still attach (APP-11.3-c).
    #[test]
    fn app11_5_harden_follows_the_build_kind() {
        let (limit, attach) = attach_to("harden");
        let refused = (attach.1, attach.2) == (libc::EBUSY, true);
        if cfg!(debug_assertions) {
            // The child kept the limit it inherited from this process.
            let (soft, hard) = core_limit();
            assert_eq!(limit, (soft.to_string(), hard.to_string()));
            assert!(!refused, "{attach:?}");
        } else {
            assert_eq!(limit, ("0".into(), "0".into()));
            assert!(refused, "{attach:?}");
        }
    }
}
