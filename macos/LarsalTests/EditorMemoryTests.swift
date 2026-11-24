import AppKit
import Darwin
import LarsalCore
import Testing

/// A random demo password the test holds only masked (`masked[n] ^
/// mask[n]`), so the scan never finds the test's own copy (AT-E07, F-102).
struct MaskedNeedle {
    let masked: [UInt8]
    let mask: [UInt8]

    init(length: Int = 24) {
        let letters = Array("abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789".utf8)
        var mask: [UInt8] = []
        var masked: [UInt8] = []
        for _ in 0..<length {
            let key = UInt8.random(in: 1...255)
            mask.append(key)
            masked.append((letters.randomElement() ?? 65) ^ key)
        }
        self.mask = mask
        self.masked = masked
    }

    /// The plain text, made only for the one call that hands it to Rust.
    func plain() -> String { String(bytes: zip(masked, mask).map { $0 ^ $1 }, encoding: .utf8) ?? "" }

    /// The needle as UTF-16LE, still masked.
    var utf16: MaskedNeedle {
        var mask16: [UInt8] = []
        var masked16: [UInt8] = []
        for (byte, key) in zip(masked, mask) {
            mask16 += [key, 0x5A]
            masked16 += [byte, 0x5A]
        }
        return MaskedNeedle(masked: masked16, mask: mask16)
    }

    private init(masked: [UInt8], mask: [UInt8]) {
        self.masked = masked
        self.mask = mask
    }
}

/// Counts the copies of a masked needle in this process's memory, as the
/// E13-S2 red team scanned (RT-E-2): every readable region that is private
/// or writable (`mach_vm_region_recurse`), only the pages `mincore` reports
/// resident or paged out, read with `mach_vm_read_overwrite`.
final class MemoryScan {
    private let page = Int(getpagesize())
    /// Pages per `mincore` call.
    private let batch = 4096
    private let needle: MaskedNeedle
    private let window: UnsafeMutableRawBufferPointer
    private let flags: UnsafeMutablePointer<CChar>
    private var carried = 0
    private var found = 0

    private init(_ needle: MaskedNeedle) {
        self.needle = needle
        window = .allocate(byteCount: page + needle.masked.count, alignment: 16)
        flags = .allocate(capacity: batch)
    }

    isolated deinit {
        window.initializeMemory(as: UInt8.self, repeating: 0)
        window.deallocate()
        flags.deallocate()
    }

    static func count(_ needle: MaskedNeedle) -> Int {
        let scan = MemoryScan(needle)
        var address: mach_vm_address_t = 0
        var depth: natural_t = 0
        while let region = next(&address, &depth) {
            if region.scan { scan.region(region.start, region.size) }
        }
        return scan.found
    }

    private struct Region {
        let start: mach_vm_address_t
        let size: mach_vm_size_t
        /// Readable, and private or writable.
        let scan: Bool
    }

    /// The next region at or after `address`.
    private static func next(_ address: inout mach_vm_address_t, _ depth: inout natural_t) -> Region? {
        while true {
            var size: mach_vm_size_t = 0
            var info = vm_region_submap_info_data_64_t()
            var count = mach_msg_type_number_t(
                MemoryLayout<vm_region_submap_info_data_64_t>.size / MemoryLayout<natural_t>.size)
            let result = withUnsafeMutablePointer(to: &info) { pointer in
                pointer.withMemoryRebound(to: Int32.self, capacity: Int(count)) {
                    mach_vm_region_recurse(mach_task_self_, &address, &size, &depth, $0, &count)
                }
            }
            guard result == KERN_SUCCESS else { return nil }
            if info.is_submap != 0 {
                depth += 1
                continue
            }
            let start = address
            address += size
            let readable = info.protection & VM_PROT_READ != 0
            let writable = info.protection & VM_PROT_WRITE != 0
            let isPrivate = info.share_mode == SM_PRIVATE || info.share_mode == SM_PRIVATE_ALIASED
            return Region(start: start, size: size, scan: readable && (writable || isPrivate))
        }
    }

    /// One region, `batch` pages per `mincore` call.
    private func region(_ start: mach_vm_address_t, _ size: mach_vm_size_t) {
        carried = 0
        var cursor = start
        let end = start + size
        while cursor < end {
            let pages = min(batch, Int((end - cursor) / mach_vm_size_t(page)))
            guard pages > 0 else { return }
            let known = mincore(UnsafeMutableRawPointer(bitPattern: UInt(cursor)), pages * page, flags) == 0
            for index in 0..<pages {
                // 0x1 resident, 0x20 paged out.
                let kept = known && flags[index] & 0x21 != 0
                readPage(cursor + mach_vm_address_t(index * page), kept: kept)
            }
            cursor += mach_vm_address_t(pages * page)
        }
    }

    /// One page; the last bytes of a page carry over to the next one, so a
    /// copy across two pages counts once.
    private func readPage(_ address: mach_vm_address_t, kept: Bool) {
        var read: mach_vm_size_t = 0
        let target = mach_vm_address_t(UInt(bitPattern: window.baseAddress) + UInt(carried))
        let size = mach_vm_size_t(page)
        guard kept, mach_vm_read_overwrite(mach_task_self_, address, size, target, &read) == KERN_SUCCESS else {
            carried = 0
            return
        }
        let filled = carried + page
        matches(filled)
        // Keep the page's last bytes and clear the rest, so a later read of
        // this buffer's own page finds no copy here.
        let carry = needle.masked.count - 1
        window.copyMemory(from: UnsafeRawBufferPointer(rebasing: window[(filled - carry)..<filled]))
        UnsafeMutableRawBufferPointer(rebasing: window[carry...]).initializeMemory(as: UInt8.self, repeating: 0)
        carried = carry
    }

    /// `memchr` finds each place the first byte is (an unoptimised loop
    /// over every byte would take minutes), then the rest is compared.
    private func matches(_ filled: Int) {
        let length = needle.masked.count
        guard let base = window.baseAddress else { return }
        let first = Int32(needle.masked[0] ^ needle.mask[0])
        var from = 0
        while from <= filled - length {
            guard let hit = memchr(base + from, first, filled - length + 1 - from) else { return }
            let start = base.distance(to: hit)
            if (1..<length).allSatisfy({ window[start + $0] == needle.masked[$0] ^ needle.mask[$0] }) { found += 1 }
            from = start + 1
        }
    }
}

/// F-102 (E13-S2 AT-E07, RT-E-2): the entry editor's Show and Hide, drawn
/// in the real main window offscreen, leave no copy of the password in Larsal's
/// memory once the vault is locked and closed. Never on the owner's screen:
/// the window is never ordered front (AGENTS.md rule 10).
@MainActor
@Suite(.serialized)
struct EditorMemoryTests {
    init() { ParityDemo.setUp() }

    @Test("F-102, AT-E07: the editor's Show and Hide leave no copy of the password after lock and close")
    func f102EditorShowLeavesNoCopy() async throws {
        let needle = MaskedNeedle()
        let window = try ParityDemo.window("f102")
        let main = try #require(window.main)
        let id = main.vault.id
        main.select(try githubID(main))
        main.edit()
        let editor = try #require(main.editor)
        autoreleasepool { editor.maskedTyped(needle.plain()) }
        let screen = Screen(window)
        await screen.settle()
        editor.toggleShowPassword()
        await screen.settle()
        screen.host.display()
        let shown = MemoryScan.count(needle)
        #expect(shown > 0, "the scan finds the shown password: \(shown)")
        editor.toggleShowPassword()
        await screen.settle()
        screen.host.display()
        main.closeEditor()
        window.lock(id)
        window.close(id)
        await screen.settle()
        screen.host.display()
        let utf8 = MemoryScan.count(needle)
        let utf16 = MemoryScan.count(needle.utf16)
        #expect(utf8 == 0 && utf16 == 0, "copies after lock and close: \(utf8) UTF-8, \(utf16) UTF-16")
    }
}
