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
        fn mach_vm_read_overwrite(
            task: libc::c_uint,
            address: u64,
            size: u64,
            data: u64,
            outsize: *mut u64,
        ) -> libc::c_int;
    }
    const REGION_BASIC_INFO_64: libc::c_int = 9;
    const REGION_BASIC_INFO_COUNT_64: libc::c_uint = 9;
    /// The bytes the search reads from the kernel at a time.
    const PIECE: usize = 1 << 20;

    /// How many copies of a span this process's writable memory holds: heap,
    /// freed blocks and stacks. `masked` is the span with each byte XOR `mask`,
    /// so the search never finds its own needle. F-439 (C1R2-3, C1R3-2): the
    /// memory is read a piece at a time with `mach_vm_read_overwrite` into a
    /// buffer of the probe's own, mapped for the search and outside the heap;
    /// for a piece that another thread unmapped or protected meanwhile the
    /// kernel answers an error, never a fault, and the search asks
    /// `mach_vm_region` again from that address and goes on with what is
    /// still mapped readable and writable there ([`in_region`]); it prints the
    /// bytes it could not read. So other threads may run, map and unmap during
    /// the search. The count is exact for the memory that stays mapped
    /// readable and writable through the search, and only while no other
    /// thread makes, frees or wipes a copy meanwhile, so a test that counts
    /// copies still runs alone in its program.
    ///
    /// # Panics
    /// When `masked` is empty, or no memory is left for the buffer.
    #[must_use]
    pub fn copies_in_memory(masked: &[u8], mask: u8) -> usize {
        assert!(!masked.is_empty(), "an empty span");
        let mut buf = Buffer::new(PIECE + masked.len() - 1);
        let (mut found, mut skipped) = (0, 0);
        let mut address = 0_u64;
        while let Some((start, size, readable_and_writable)) = region(address) {
            let Ok(len) = usize::try_from(size) else {
                break;
            };
            if readable_and_writable && len >= masked.len() {
                let (n, lost) = in_region(start, len, buf.bytes(), masked, mask);
                found += n;
                skipped += lost;
            }
            address = start + size;
        }
        if skipped > 0 {
            println!(
                "copies_in_memory: {skipped} bytes skipped, gone or refused during the search"
            );
        }
        found
    }

    /// The region `mach_vm_region` lists now at or above `address`: its
    /// start, its size and whether it is readable and writable; `None` past
    /// the last.
    fn region(address: u64) -> Option<(u64, u64, bool)> {
        let (mut address, mut size, mut object) = (address, 0_u64, 0);
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
        (result == 0).then_some((address, size, info[0] & 3 == 3))
    }

    /// The first readable and writable part, at or above `at` and below
    /// `end`, of what `mach_vm_region` lists now: its start and end.
    fn part(mut at: u64, end: u64) -> Option<(u64, u64)> {
        while at < end {
            let (start, size, readable_and_writable) = region(at)?;
            let (from, to) = (start.max(at), (start + size).min(end));
            if from >= end {
                return None;
            }
            if readable_and_writable {
                return Some((from, to));
            }
            at = to;
        }
        None
    }

    /// The copies in the `len` bytes of this process's memory from `start` (a
    /// region as `mach_vm_region` listed it), and how many of its bytes the
    /// search could not read. They are read into `buf` a piece at a time: a
    /// piece is `buf.len()` bytes or what is left, and the next one starts
    /// `masked.len() - 1` bytes before its end, so a copy across two pieces
    /// is counted once, in the first. Before a piece that takes in the
    /// buffer's own memory, `buf` is zeroed, so the search never finds what
    /// it read itself. A piece the kernel refuses (another thread unmapped or
    /// protected memory there meanwhile): the search asks `mach_vm_region`
    /// again from that address and goes on with what is still mapped readable
    /// and writable in the listed bytes ([`part`]), after a hole too; the
    /// bytes it passes over count as skipped, as does a part the kernel
    /// refuses again unchanged. A copy across the end of a part that the
    /// kernel lists apart is not counted, as across two regions.
    fn in_region(start: u64, len: usize, buf: &mut [u8], masked: &[u8], mask: u8) -> (usize, u64) {
        let step = buf.len() + 1 - masked.len();
        let first = anchor(masked, mask);
        let own = buf.as_ptr() as u64..buf.as_ptr() as u64 + buf.len() as u64;
        let (span, end) = (masked.len() as u64, start + len as u64);
        // The part being read, `at` to `stop`: the whole region until a piece
        // is refused.
        let (mut at, mut stop) = (start, end);
        let (mut found, mut skipped) = (0, 0);
        loop {
            if at + span > stop {
                // This part is done; on to what is mapped past it, if any.
                if stop >= end {
                    break;
                }
                let Some((from, to)) = part(stop, end) else {
                    skipped += end - stop;
                    break;
                };
                skipped += from - stop;
                (at, stop) = (from, to);
                continue;
            }
            let want = buf
                .len()
                .min(usize::try_from(stop - at).unwrap_or(usize::MAX));
            if at < own.end && own.start < at + want as u64 {
                buf.fill(0);
            }
            let mut got = 0_u64;
            // SAFETY: the kernel writes at most `want` bytes, no more than
            // `buf.len()`, into `buf`, which is ours and writable, and reads
            // the source range itself: a range no longer mapped readable gets
            // an error code, not a fault in this process. No Rust object is
            // formed over the source memory.
            let result = unsafe {
                mach_vm_read_overwrite(
                    mach_task_self_,
                    at,
                    want as u64,
                    buf.as_mut_ptr() as u64,
                    &raw mut got,
                )
            };
            if result == 0 && got == want as u64 {
                found += count(&buf[..want], masked, mask, first, step);
                at += step as u64;
                continue;
            }
            // Refused: what is still mapped readable and writable from here?
            match part(at, end) {
                Some((from, to)) if from > at || to < stop => {
                    skipped += from - at;
                    (at, stop) = (from, to);
                }
                // Nothing, or this part again unchanged: passed over.
                _ => {
                    skipped += stop - at;
                    at = stop;
                }
            }
        }
        (found, skipped)
    }

    /// Where in the span the byte is that the search looks for first: the
    /// first byte that is neither 0x00 nor 0xFF, which fill most memory, else
    /// the first 0xFF, else the first. A span that starts with 0x00 would
    /// stop the search at nearly every byte (F-439: qr_t29's spans of 0x00,
    /// 0x01 and 0xFF bytes); the count is the same.
    fn anchor(masked: &[u8], mask: u8) -> usize {
        let plain = |b: &u8| b ^ mask;
        masked
            .iter()
            .position(|b| !matches!(plain(b), 0x00 | 0xFF))
            .or_else(|| masked.iter().position(|b| plain(b) == 0xFF))
            .unwrap_or(0)
    }

    /// The copies in `hay` that start before `limit`, found by their byte at
    /// `first` (see [`anchor`]).
    fn count(hay: &[u8], masked: &[u8], mask: u8, first: usize, limit: usize) -> usize {
        let Some(last) = hay.len().checked_sub(masked.len()) else {
            return 0;
        };
        let end = limit.min(last + 1);
        let byte = libc::c_int::from(masked[first] ^ mask);
        let (mut at, mut found) = (0, 0);
        while at < end {
            // SAFETY: memchr reads `end - at` bytes from `hay[at + first]`;
            // the last is `hay[end - 1 + first]`, at most `hay[last + first]`,
            // inside the slice since `first < masked.len()`.
            let hit = unsafe { libc::memchr(hay[at + first..].as_ptr().cast(), byte, end - at) };
            if hit.is_null() {
                break;
            }
            let here = hit as usize - hay.as_ptr() as usize - first;
            let same = hay[here..here + masked.len()]
                .iter()
                .zip(masked)
                .all(|(b, want)| b ^ mask == *want);
            found += usize::from(same);
            at = here + 1;
        }
        found
    }

    /// The search's own buffer: anonymous memory mapped for one search and
    /// unmapped after it, so the search takes no block of the heap.
    struct Buffer(*mut u8, usize);

    impl Buffer {
        fn new(len: usize) -> Self {
            // SAFETY: an anonymous private mapping of `len` bytes touches no
            // memory of ours; the result is checked before any use.
            let at = unsafe {
                libc::mmap(
                    std::ptr::null_mut(),
                    len,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_PRIVATE | libc::MAP_ANON,
                    -1,
                    0,
                )
            };
            assert!(at != libc::MAP_FAILED, "no memory for the search");
            Self(at.cast(), len)
        }

        fn bytes(&mut self) -> &mut [u8] {
            // SAFETY: `self.1` bytes from `self.0` are the mapping `new`
            // made, zero-filled by the kernel, written only through this
            // slice and the kernel's copies into it, and mapped until drop;
            // `&mut self` keeps this the only slice over it.
            unsafe { std::slice::from_raw_parts_mut(self.0, self.1) }
        }
    }

    impl Drop for Buffer {
        fn drop(&mut self) {
            // SAFETY: the mapping `new` made, unmapped once; no slice over it
            // outlives `&mut self`.
            unsafe { libc::munmap(self.0.cast(), self.1) };
        }
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

    /// F-439 (C1R2-3, C1R3-2): the search never faults while another thread
    /// maps and unmaps memory, reads a region in pieces as one whole, and
    /// goes on past a part that is gone.
    #[cfg(test)]
    mod tests {
        use super::{anchor, copies_in_memory, in_region};
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering::Relaxed};

        const MASK: u8 = 0xA5;
        /// The other thread's region: 64 MiB, never touched, so reading it
        /// takes the search a while.
        const CHURN: usize = 64 << 20;

        /// Another thread maps a 64 MiB region, keeps it a millisecond and
        /// unmaps it, again and again, while the probe searches all writable
        /// memory five times; the searches start once it has unmapped one
        /// (an event, so a busy Mac cannot start them first). A search that
        /// read unmapped memory would end the program on SIGSEGV; the
        /// kernel's copy answers an error instead. A copy planted here is
        /// found every time.
        #[test]
        fn copies_in_memory_never_faults_while_another_thread_unmaps() {
            let plain: Vec<u8> = (0..64_u8).map(|i| i.wrapping_mul(29) ^ 0xC3).collect();
            let masked: Vec<u8> = plain.iter().map(|b| b ^ MASK).collect();
            let stop = Arc::new(AtomicBool::new(false));
            let rounds = Arc::new(AtomicUsize::new(0));
            let churn = {
                let (stop, rounds) = (Arc::clone(&stop), Arc::clone(&rounds));
                std::thread::spawn(move || {
                    let mut unmapped = 0_usize;
                    while !stop.load(Relaxed) {
                        // SAFETY: an anonymous mapping of our own, never
                        // read or written here, unmapped once by this thread.
                        unsafe {
                            let at = libc::mmap(
                                std::ptr::null_mut(),
                                CHURN,
                                libc::PROT_READ | libc::PROT_WRITE,
                                libc::MAP_PRIVATE | libc::MAP_ANON,
                                -1,
                                0,
                            );
                            if at != libc::MAP_FAILED {
                                std::thread::sleep(std::time::Duration::from_millis(1));
                                libc::munmap(at, CHURN);
                                unmapped += 1;
                            }
                        }
                        rounds.store(unmapped, Relaxed);
                    }
                    unmapped
                })
            };
            // A hang backstop only: the other thread's first unmap takes
            // about a millisecond.
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
            while rounds.load(Relaxed) == 0 {
                assert!(std::time::Instant::now() < deadline, "no unmap in 30 s");
                std::thread::yield_now();
            }
            let found: Vec<usize> = (0..5).map(|_| copies_in_memory(&masked, MASK)).collect();
            stop.store(true, Relaxed);
            let unmapped = churn.join().unwrap();
            std::hint::black_box(&plain);
            println!("the other thread unmapped {unmapped} regions; found {found:?}");
            assert!(found.iter().all(|&n| n >= 1), "the planted copy: {found:?}");
        }

        /// F-439 (C1R3-2, Checker 1's TH): a region listed whole, then part
        /// of it protected or unmapped by the time it is read. The search
        /// reads a refused piece again up to the hole, goes on after it, and
        /// counts the bytes it passed over. Copies at 0.5, 1.25 and 3.5 MiB:
        /// with 1.5 to 2 MiB protected all three count; with the first MiB
        /// protected too, the two still readable; with the first MiB
        /// unmapped instead (TH), the same two, still mapped and made, freed
        /// or wiped by nobody.
        #[test]
        fn a_copy_past_a_hole_is_counted() {
            const MIB: usize = 1 << 20;
            let needle = *b"F439-hole-builder-4!";
            let masked: Vec<u8> = needle.iter().map(|b| b ^ MASK).collect();
            let mut buf = vec![0_u8; super::PIECE + masked.len() - 1];
            // SAFETY: an anonymous mapping of our own; the copies are written
            // inside it before any part of it is protected or unmapped; then
            // it is read only by the kernel's copy, and unmapped at the end.
            let (protected, both, unmapped) = unsafe {
                let at = libc::mmap(
                    std::ptr::null_mut(),
                    4 * MIB,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_PRIVATE | libc::MAP_ANON,
                    -1,
                    0,
                );
                assert!(at != libc::MAP_FAILED);
                let base = at.cast::<u8>();
                for place in [MIB / 2, MIB + MIB / 4, 3 * MIB + MIB / 2] {
                    std::ptr::copy_nonoverlapping(needle.as_ptr(), base.add(place), needle.len());
                }
                let hole = base.add(MIB + MIB / 2).cast();
                assert_eq!(libc::mprotect(hole, MIB / 2, libc::PROT_NONE), 0);
                let start = base as u64;
                let protected = in_region(start, 4 * MIB, &mut buf, &masked, MASK);
                assert_eq!(libc::mprotect(at, MIB, libc::PROT_NONE), 0);
                let both = in_region(start, 4 * MIB, &mut buf, &masked, MASK);
                libc::munmap(at, MIB);
                let unmapped = in_region(start, 4 * MIB, &mut buf, &masked, MASK);
                libc::munmap(base.add(MIB).cast(), 3 * MIB);
                (protected, both, unmapped)
            };
            println!(
                "copies, bytes skipped: {protected:?}; the first MiB protected too: {both:?}; unmapped: {unmapped:?}"
            );
            let half = (MIB / 2) as u64;
            assert_eq!(protected, (3, half), "1.5 to 2 MiB protected");
            assert_eq!(both, (2, 3 * half), "0 to 1 and 1.5 to 2 MiB protected");
            assert_eq!(
                unmapped.0, 2,
                "the copies at 1.25 and 3.5 MiB are still mapped"
            );
            // The first MiB is a hole another thread may map meanwhile.
            assert!((half..=3 * half).contains(&unmapped.1), "{unmapped:?}");
        }

        /// A region read in pieces of 8 to 200 bytes holds its 5 copies,
        /// two of them across a piece's end at some sizes, each counted
        /// once; also for a span found by its third byte, as one that starts
        /// with 0x00 is.
        #[test]
        fn a_copy_across_two_pieces_is_counted_once() {
            for needle in [*b"F439-ab!", [0, 0, b'F', b'4', b'3', b'9', 0xFF, b'!']] {
                let masked: Vec<u8> = needle.iter().map(|b| b ^ MASK).collect();
                let mut region = [0_u8; 100];
                for at in [0, 13, 40, 61, 92] {
                    region[at..at + 8].copy_from_slice(&needle);
                }
                for piece in [8, 9, 16, 23, 200] {
                    let mut buf = vec![0_u8; piece + needle.len() - 1];
                    let start = region.as_ptr() as u64;
                    let found = in_region(start, region.len(), &mut buf, &masked, MASK);
                    assert_eq!(found, (5, 0), "pieces of {piece}, {needle:?}");
                }
            }
        }

        /// The byte looked for first: not 0x00 or 0xFF where the span has
        /// another, else 0xFF, else the first.
        #[test]
        fn the_search_looks_first_for_a_rare_byte() {
            let at = |plain: &[u8]| {
                let masked: Vec<u8> = plain.iter().map(|b| b ^ MASK).collect();
                anchor(&masked, MASK)
            };
            assert_eq!(at(b"F439"), 0);
            assert_eq!(at(&[0, 0xFF, 0, 1, 7]), 3);
            assert_eq!(at(&[0, 0, 0xFF, 0]), 2);
            assert_eq!(at(&[0, 0, 0]), 0);
        }

        /// The buffer still holds a copy from the piece before when the
        /// search comes to the buffer's own memory: that copy is not counted.
        #[test]
        fn the_search_never_counts_its_own_buffer() {
            let needle = *b"F439-ab!";
            let masked: Vec<u8> = needle.iter().map(|b| b ^ MASK).collect();
            let mut buf = [0_u8; 64];
            buf[20..28].copy_from_slice(&needle);
            let start = buf.as_ptr() as u64;
            let len = buf.len();
            assert_eq!(in_region(start, len, &mut buf, &masked, MASK), (0, 0));
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
