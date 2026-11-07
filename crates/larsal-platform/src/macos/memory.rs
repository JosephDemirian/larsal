//! The zeroing allocator of LD-133 and the page lock calls of APP-11.9
//! (SR-07, E6-S6). The safe front, with the guarantees, is `crate::memory`.

use std::alloc::{GlobalAlloc, Layout};
use std::io;

/// An allocator that zeroes every block before handing it back to `A`
/// (LD-133). A binary installs it as
/// `#[global_allocator] static ALLOC: Zeroing<System> = Zeroing(System);`.
///
/// `realloc` is left to the trait's default on purpose: allocate, copy, free
/// through `dealloc`, so the old block of a moved buffer is zeroed too. The
/// system's in-place `realloc` would hand the old block back unwiped.
pub struct Zeroing<A>(pub A);

// SAFETY: every method passes the caller's pointer and layout unchanged to
// `A`, which keeps the GlobalAlloc contract; `dealloc` only writes zeros into
// the block the caller is giving up, before `A` gets it. Nothing here
// allocates, panics or unwinds.
unsafe impl<A: GlobalAlloc> GlobalAlloc for Zeroing<A> {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: the caller's contract for `alloc` is passed on unchanged.
        unsafe { self.0.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        // SAFETY: as for `alloc`.
        unsafe { self.0.alloc_zeroed(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: the caller guarantees `ptr` came from this allocator with
        // `layout`, so `layout.size()` bytes at `ptr` are a block of ours,
        // live until `A::dealloc` takes it back; the same pointer and layout
        // go to `A`, which made the block.
        unsafe {
            wipe(ptr, layout.size());
            self.0.dealloc(ptr, layout);
        }
    }
}

/// Zeroes `len` bytes at `ptr` with C11 `memset_s` (Annex K.3.7.4.1: the
/// call is carried out strictly as the abstract machine says, so unlike
/// `memset` or a plain write before `free` the compiler may not drop it;
/// libsodium's `sodium_memzero` uses it on macOS for the same reason).
///
/// # Safety
/// `ptr` is valid for writes of `len` bytes.
unsafe fn wipe(ptr: *mut u8, len: usize) {
    if len != 0 {
        // SAFETY: the caller guarantees `len` writable bytes at `ptr`; with
        // `smax == n` memset_s writes exactly those. `len` comes from a
        // Layout, so it is at most isize::MAX, which is macOS's RSIZE_MAX:
        // the call cannot fail.
        unsafe { libc::memset_s(ptr.cast(), len, 0, len) };
    }
}

/// The VM page size: 16 KiB on Apple silicon.
#[must_use]
pub fn page_size() -> usize {
    // SAFETY: sysconf reads and writes no memory of ours.
    let n = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    usize::try_from(n)
        .ok()
        .filter(|n| n.is_power_of_two())
        .unwrap_or(16384)
}

/// `mlock(2)` on `len` bytes from the page-aligned address `start`. Locks
/// nest per page (the kernel counts them), so each successful call needs its
/// own [`munlock`]. On failure (EAGAIN at RLIMIT_MEMLOCK or the system wired
/// limit, ENOMEM for an unmapped range) no page changed.
pub(crate) fn mlock(start: usize, len: usize) -> io::Result<()> {
    // SAFETY: mlock reads and writes no memory of ours, it only wires pages;
    // an unmapped or misaligned range makes it fail with ENOMEM or EINVAL.
    if unsafe { libc::mlock(start as *const libc::c_void, len) } == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// `munlock(2)`: undoes one [`mlock`] of the same range.
pub(crate) fn munlock(start: usize, len: usize) -> io::Result<()> {
    // SAFETY: as for mlock; munlock only unwires pages.
    if unsafe { libc::munlock(start as *const libc::c_void, len) } == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(any(test, feature = "test-memory"))]
pub use probe::{
    Probe, Seen, copies_in_memory, marker_survives_free, set_needle, wired_bytes,
    zero_stack_words_after,
};

/// Test tools only (feature `test-memory`, never in product builds).
#[cfg(any(test, feature = "test-memory"))]
mod probe {
    use std::alloc::{GlobalAlloc, Layout, System};
    use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering::Relaxed};

    /// The 8 bytes [`Probe`] looks for; all zero means none.
    static NEEDLE: AtomicU64 = AtomicU64::new(0);
    static ZEROS: [u8; 4096] = [0; 4096];

    /// Sets the 8 bytes every [`Probe`] looks for in the blocks handed back
    /// to it; `[0; 8]` turns the search off.
    pub fn set_needle(needle: [u8; 8]) {
        NEEDLE.store(u64::from_le_bytes(needle), Relaxed);
    }

    /// What a [`Probe`] saw in the blocks handed back to it.
    pub struct Seen {
        /// Blocks handed back.
        pub freed: AtomicUsize,
        /// Blocks that held the needle.
        pub with_needle: AtomicUsize,
        /// The largest of those, in bytes.
        pub largest_with_needle: AtomicUsize,
        /// Blocks with any byte other than zero.
        pub not_zero: AtomicUsize,
    }

    impl Seen {
        /// All counts at zero.
        #[must_use]
        pub const fn new() -> Self {
            Self {
                freed: AtomicUsize::new(0),
                with_needle: AtomicUsize::new(0),
                largest_with_needle: AtomicUsize::new(0),
                not_zero: AtomicUsize::new(0),
            }
        }

        /// Sets all counts back to zero.
        pub fn reset(&self) {
            for n in [
                &self.freed,
                &self.with_needle,
                &self.largest_with_needle,
                &self.not_zero,
            ] {
                n.store(0, Relaxed);
            }
        }
    }

    impl Default for Seen {
        fn default() -> Self {
            Self::new()
        }
    }

    /// An allocator that looks at each block handed back to it (the needle,
    /// any byte other than zero) and then passes it on to `A` unchanged.
    /// Stacked around and inside [`super::Zeroing`], it shows what a block
    /// held before the wipe and what reaches the system after it, with no
    /// read of freed memory.
    pub struct Probe<A>(pub A, pub &'static Seen);

    // SAFETY: every method passes the caller's pointer and layout unchanged
    // to `A`; `dealloc` only reads the block before passing it on. Nothing
    // here allocates, panics or unwinds.
    unsafe impl<A: GlobalAlloc> GlobalAlloc for Probe<A> {
        unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
            // SAFETY: the caller's contract for `alloc` is passed on.
            unsafe { self.0.alloc(layout) }
        }

        unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
            // SAFETY: as for `alloc`.
            unsafe { self.0.alloc_zeroed(layout) }
        }

        unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
            let seen = self.1;
            let len = layout.size();
            let needle = NEEDLE.load(Relaxed).to_le_bytes();
            seen.freed.fetch_add(1, Relaxed);
            // SAFETY: the caller guarantees `len` bytes at `ptr` are a live
            // block of ours until `A::dealloc`. They are read only through
            // memmem and memcmp, as unsigned char, which C defines even for
            // bytes never written (a block's spare capacity), so no Rust
            // reference to possibly uninitialized bytes is made. The needle
            // and ZEROS are 8 and 4,096 readable bytes; each memcmp reads at
            // most 4,096 bytes inside the block. Then the same pointer and
            // layout go to `A`.
            unsafe {
                if needle != [0; 8]
                    && !libc::memmem(ptr.cast(), len, needle.as_ptr().cast(), 8).is_null()
                {
                    seen.with_needle.fetch_add(1, Relaxed);
                    seen.largest_with_needle.fetch_max(len, Relaxed);
                }
                let mut at = 0;
                while at < len {
                    let n = (len - at).min(ZEROS.len());
                    if libc::memcmp(ptr.add(at).cast(), ZEROS.as_ptr().cast(), n) != 0 {
                        seen.not_zero.fetch_add(1, Relaxed);
                        break;
                    }
                    at += n;
                }
                self.0.dealloc(ptr, layout);
            }
        }
    }

    // <mach/mach_vm.h>, with VM_REGION_BASIC_INFO_64 and its count.
    unsafe extern "C" {
        static mach_task_self_: libc::c_uint;
        fn mach_vm_region(
            task: libc::c_uint,
            address: *mut u64,
            size: *mut u64,
            flavor: libc::c_int,
            info: *mut libc::c_int,
            count: *mut libc::c_uint,
            object: *mut libc::c_uint,
        ) -> libc::c_int;
    }
    const REGION_BASIC_INFO_64: libc::c_int = 9;
    const REGION_BASIC_INFO_COUNT_64: libc::c_uint = 9;

    /// How many copies of a span this process's writable memory holds: heap,
    /// freed blocks and stacks. `masked` is the span with each byte XOR `mask`,
    /// so the search never finds its own needle. For a test program that runs
    /// this one test alone: nothing may unmap memory during the search. Reads
    /// only through `memchr` and single byte reads of mapped pages.
    ///
    /// # Panics
    /// When `masked` is empty.
    #[must_use]
    pub fn copies_in_memory(masked: &[u8], mask: u8) -> usize {
        let first = libc::c_int::from(masked[0] ^ mask);
        let mut found = 0;
        let mut address = 0_u64;
        loop {
            let (mut size, mut object) = (0_u64, 0);
            let mut info = [0; 16];
            let mut count = REGION_BASIC_INFO_COUNT_64;
            // SAFETY: the out pointers are valid locals; `info` is larger than
            // the 9 ints the count asks for; the call only asks the kernel about
            // this task.
            let result = unsafe {
                mach_vm_region(
                    mach_task_self_,
                    &raw mut address,
                    &raw mut size,
                    REGION_BASIC_INFO_64,
                    info.as_mut_ptr(),
                    &raw mut count,
                    &raw mut object,
                )
            };
            if result != 0 {
                return found;
            }
            let readable_and_writable = info[0] & 3 == 3;
            let Ok(len) = usize::try_from(size) else {
                return found;
            };
            if readable_and_writable && len >= masked.len() {
                let start = address as usize;
                found += in_region(start, len, masked, mask, first);
            }
            address += size;
        }
    }

    /// The copies in one mapped region of `len` bytes from `start`.
    fn in_region(start: usize, len: usize, masked: &[u8], mask: u8, first: libc::c_int) -> usize {
        let (mut at, mut found) = (0, 0);
        let last = len - masked.len();
        while at <= last {
            // SAFETY: the kernel just reported the region mapped read and
            // write, and the caller keeps it so (the test runs alone); memchr
            // reads bytes as unsigned char inside it. The pointer is made from
            // the address on purpose: no Rust object is formed over this memory.
            let hit =
                unsafe { libc::memchr((start + at) as *const libc::c_void, first, last - at + 1) };
            if hit.is_null() {
                break;
            }
            let here = hit as usize;
            // SAFETY: `here` is at most `start + last`, so every byte read lies
            // in the region; volatile, so each is a real read of that byte.
            let same = masked.iter().enumerate().all(|(i, want)| unsafe {
                ((here + i) as *const u8).read_volatile() ^ mask == *want
            });
            found += usize::from(same);
            at = here - start + 1;
        }
        found
    }

    /// The bytes this process has wired (`proc_pid_rusage`, `ri_wired_size`):
    /// the test hook of APP-11.9-b (AT-C05).
    ///
    /// # Panics
    /// When the call fails, which it does only for another process's id.
    #[must_use]
    pub fn wired_bytes() -> u64 {
        let mut info = std::mem::MaybeUninit::<libc::rusage_info_v2>::zeroed();
        // SAFETY: `info` is valid for writes of a rusage_info_v2, the struct
        // of flavor RUSAGE_INFO_V2; it starts zeroed, so it is valid whatever
        // the call writes, and assume_init runs only after it returned 0.
        unsafe {
            let rc = libc::proc_pid_rusage(
                libc::getpid(),
                libc::RUSAGE_INFO_V2,
                info.as_mut_ptr().cast(),
            );
            assert_eq!(rc, 0, "{}", std::io::Error::last_os_error());
            info.assume_init().ri_wired_size
        }
    }

    /// Frees a 66,770-byte block that holds a run of 0x5A bytes, through the
    /// process's global allocator (`through_global`) or straight through
    /// `System`; then takes a block of the same size until the allocator
    /// hands back the same address, and says whether the run is still in it.
    /// macOS 26 keeps the bytes of a freed block this size (it zeroes only
    /// small ones), so `System` says true and a zeroing global allocator
    /// false. This proves which allocator a linked binary uses without
    /// reading freed memory: the block is read only once it is ours again.
    ///
    /// # Panics
    /// When 100 tries never give the same address back.
    #[must_use]
    pub fn marker_survives_free(through_global: bool) -> bool {
        const RUN: [u8; 32] = [0x5A; 32];
        let Ok(layout) = Layout::from_size_align(66_770, 16) else {
            unreachable!("a valid layout")
        };
        for _ in 0..100 {
            // SAFETY: the layout has a non-zero size; each block is written
            // (memset_s: not dropped by the compiler) and read only while it
            // is ours, and freed once, by the allocator that made it, with
            // the same layout. The run is searched with memmem, which reads
            // the new block's bytes as unsigned char (defined in C even for
            // bytes Rust calls uninitialized); `first` is only compared as an
            // address, never read after it is freed.
            unsafe {
                let first = take(through_global, layout);
                assert!(!first.is_null(), "out of memory");
                libc::memset_s(first.cast(), layout.size(), 0x5A, layout.size());
                give(through_global, first, layout);
                let again = take(through_global, layout);
                assert!(!again.is_null(), "out of memory");
                let same = again == first;
                let kept = same
                    && !libc::memmem(again.cast(), layout.size(), RUN.as_ptr().cast(), RUN.len())
                        .is_null();
                give(through_global, again, layout);
                if same {
                    return kept;
                }
            }
        }
        panic!("the allocator never gave the same block back");
    }

    /// 16-byte words of stack that [`zero_stack_words_after`] paints: 64 KiB.
    const STACK_WORDS: usize = 4096;

    /// Paints 64 KiB of this thread's stack just below the caller with 0xA5,
    /// runs `f`, and returns the longest run of all-zero 16-byte words in
    /// that area afterwards: the stack check of LD-261 (4). Larsal's stack wipe
    /// (`larsal_crypto::secret::scrubbed`) zeroes 32 KiB (2,048 words) below
    /// the call it wraps, so a call under it gives close to 2,048; a call
    /// without it leaves the paint, so a few words at most. The paint makes
    /// the difference: fresh stack pages are zero too. Only this thread's
    /// own stack is read, and only through `memcmp`.
    #[inline(never)]
    pub fn zero_stack_words_after(f: impl FnOnce()) -> usize {
        let area = paint();
        f();
        longest_zero_run(area)
    }

    /// The address of a painted 64 KiB local; its frame ends when this returns,
    /// so the next calls of the caller run over it.
    #[inline(never)]
    fn paint() -> usize {
        let mut area = [u128::from_ne_bytes([0xA5; 16]); STACK_WORDS];
        std::hint::black_box(&mut area);
        std::hint::black_box(area.as_ptr() as usize)
    }

    #[inline(never)]
    fn longest_zero_run(area: usize) -> usize {
        let (mut run, mut longest) = (0, 0);
        for word in 0..STACK_WORDS {
            // SAFETY: `area` is the start of the 64 KiB that `paint` wrote on
            // this thread's stack, below the caller of `zero_stack_words_after`.
            // `paint`'s prologue touched each page (stack probes) and memset
            // wrote all of it, and macOS never unmaps a live thread's stack
            // pages, so it is mapped and readable, also when release builds
            // tail-call this function and the wrapper's frame is gone. In
            // Rust's model `paint`'s array is dead here, so the read is outside
            // the language: it is sound only because the compiler cannot tie
            // the address to that array (an integer through `black_box`, out
            // of an `inline(never)` function) and libc's memcmp reads the
            // bytes, 16 at a time inside the area, as unsigned char. Never read
            // the area with a Rust load or slice. ZEROS has 4,096 readable
            // bytes; no Rust value is made from the area.
            let zero = unsafe {
                libc::memcmp(
                    (area + 16 * word) as *const libc::c_void,
                    ZEROS.as_ptr().cast(),
                    16,
                ) == 0
            };
            run = if zero { run + 1 } else { 0 };
            longest = longest.max(run);
        }
        longest
    }

    /// # Safety
    /// As `GlobalAlloc::alloc`.
    unsafe fn take(through_global: bool, layout: Layout) -> *mut u8 {
        // SAFETY: passed on from the caller.
        unsafe {
            if through_global {
                std::alloc::alloc(layout)
            } else {
                System.alloc(layout)
            }
        }
    }

    /// # Safety
    /// As `GlobalAlloc::dealloc`, for a block [`take`] made with the same
    /// `through_global`.
    unsafe fn give(through_global: bool, ptr: *mut u8, layout: Layout) {
        // SAFETY: passed on from the caller.
        unsafe {
            if through_global {
                std::alloc::dealloc(ptr, layout);
            } else {
                System.dealloc(ptr, layout);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::alloc::System;
    use std::io::Read;
    use std::process::{Command, Stdio};
    use std::sync::atomic::Ordering::Relaxed;

    const ROLE: &str = "LARSAL_TEST_MEMORY_ROLE";

    /// Allocates `layout` through `a`, fills it with 0x5A, frees it.
    fn fill_and_free(a: &impl GlobalAlloc, layout: Layout) {
        // SAFETY: non-zero size; the block is written inside its size and
        // freed once by the allocator that made it, with the same layout.
        unsafe {
            let p = a.alloc(layout);
            assert!(!p.is_null());
            p.write_bytes(0x5A, layout.size());
            a.dealloc(p, layout);
        }
    }

    const LAYOUTS: [(usize, usize); 7] = [
        (1, 1),
        (16, 8),
        (100, 64),
        (4096, 4096),
        (40_000, 16),
        (66_770, 16),
        (1 << 20, 16),
    ];

    #[test]
    fn freed_blocks_are_zero() {
        static WIPED: Seen = Seen::new();
        static PLAIN: Seen = Seen::new();
        set_needle(*b"ZZZZZZZZ"); // 0x5A
        let zeroing = Zeroing(Probe(System, &WIPED));
        let plain = Probe(System, &PLAIN); // control: no wipe
        for (size, align) in LAYOUTS {
            let layout = Layout::from_size_align(size, align).unwrap();
            fill_and_free(&zeroing, layout);
            fill_and_free(&plain, layout);
        }
        assert_eq!(WIPED.freed.load(Relaxed), LAYOUTS.len());
        assert_eq!(
            WIPED.not_zero.load(Relaxed),
            0,
            "a block reached the system unwiped"
        );
        assert_eq!(PLAIN.not_zero.load(Relaxed), LAYOUTS.len(), "control");
        // The needle search sees what the wipe removed (blocks of 8 bytes and more).
        assert_eq!(
            PLAIN.with_needle.load(Relaxed),
            LAYOUTS.len() - 1,
            "control"
        );
    }

    #[test]
    fn realloc_wipes_the_old_block_when_it_grows_or_shrinks() {
        static SEEN: Seen = Seen::new();
        let z = Zeroing(Probe(System, &SEEN));
        let small = Layout::from_size_align(16, 1).unwrap();
        // SAFETY: each pointer is used with the layout it was made or resized
        // with; only the first 16 bytes, which realloc copied from written
        // bytes, are read; the last block is freed once.
        unsafe {
            let p = z.alloc(small);
            p.write_bytes(0x5A, 16);
            let grown = z.realloc(p, small, 4096);
            assert!(!grown.is_null());
            assert_eq!(std::slice::from_raw_parts(grown, 16), &[0x5A; 16], "copied");
            assert_eq!(SEEN.freed.load(Relaxed), 1, "the old block went back");
            grown.add(16).write_bytes(0x5A, 4096 - 16);
            let big = Layout::from_size_align(4096, 1).unwrap();
            let shrunk = z.realloc(grown, big, 16);
            assert_eq!(
                std::slice::from_raw_parts(shrunk, 16),
                &[0x5A; 16],
                "copied"
            );
            assert_eq!(SEEN.freed.load(Relaxed), 2);
            assert_eq!(
                SEEN.not_zero.load(Relaxed),
                0,
                "an old block kept its bytes"
            );
            z.dealloc(shrunk, small);
        }
        assert_eq!(SEEN.not_zero.load(Relaxed), 0);
    }

    /// The control for larsal-ffi's linked-core test: this test binary has no
    /// global allocator of its own, so both paths are the system's, and on
    /// this macOS a freed block of this size keeps its bytes.
    #[test]
    fn the_system_allocator_keeps_freed_bytes() {
        assert!(marker_survives_free(false));
        assert!(marker_survives_free(true));
    }

    /// APP-11.9-b and AT-C05: the pages under a locked key are wired, locks
    /// on a shared page nest, and the last guard dropped unwires them.
    #[test]
    fn app11_9_b_locked_pages_are_wired_until_the_last_guard_drops() {
        let page = page_size();
        let buf = vec![7u8; 3 * page];
        // 64 bytes across a page boundary: two pages.
        let key = &buf[page - 32..page + 32];
        let before = wired_bytes();
        let first = crate::memory::lock(key).expect("this Mac's limit is unlimited");
        assert_eq!(wired_bytes() - before, 2 * page as u64);
        let second = crate::memory::lock(&key[..16]).unwrap(); // the first page again
        drop(first);
        assert_eq!(
            wired_bytes() - before,
            page as u64,
            "the shared page stays locked"
        );
        drop(second);
        assert_eq!(wired_bytes(), before);
        assert!(crate::memory::lock(&[]).is_none(), "nothing to lock");
    }

    /// A child: lowers RLIMIT_MEMLOCK to `0`, asks `lock` twice and prints
    /// `locked <first> <second>`.
    #[test]
    #[ignore = "a child of app11_9_refused_lock_goes_on_with_one_warning"]
    fn memlock_child() {
        if std::env::var(ROLE).as_deref() != Ok("limit-0") {
            return;
        }
        let zero = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        // SAFETY: `zero` is a valid rlimit that setrlimit only reads.
        assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &zero) }, 0);
        let key = vec![7u8; 64];
        let first = crate::memory::lock(&key).is_some();
        let second = crate::memory::lock(&key).is_some();
        println!("locked {first} {second}");
    }

    #[test]
    fn app11_9_refused_lock_goes_on_with_one_warning() {
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "macos::memory::tests::memlock_child",
                "--ignored",
                "--nocapture",
                "--test-threads=1",
            ])
            .env(ROLE, "limit-0")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let (mut out, mut err) = (String::new(), String::new());
        child
            .stdout
            .take()
            .unwrap()
            .read_to_string(&mut out)
            .unwrap();
        child
            .stderr
            .take()
            .unwrap()
            .read_to_string(&mut err)
            .unwrap();
        assert!(child.wait().unwrap().success(), "{out}{err}");
        assert!(out.contains("locked false false"), "{out}");
        assert_eq!(err.matches(crate::hardening::M11_01).count(), 1, "{err}");
    }
}
