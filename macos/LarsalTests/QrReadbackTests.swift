import AppKit
import LarsalCore
import Testing

/// E21-S2's main check: the drawn code, read back by Core Image, holds the
/// exact bytes in ECI 26 and one byte segment (FEA-10.8, .9, .24, LD-359).
/// Every value is demo data made here. Refusals are counted apart: they never
/// count toward the 1,000.
@MainActor
@Suite(.serialized)
struct QrReadbackTests {
    init() { ParityDemo.setUp() }

    private static let pools: [[Unicode.Scalar]] = {
        let ranges: [ClosedRange<UInt32>] = [
            0x41...0x5A, 0x61...0x7A, 0x30...0x39, 0x21...0x2F, 0x20...0x20, 0x600...0x64A, 0x4E00...0x4FFF,
            0x410...0x44F, 0x904...0x939, 0x1F600...0x1F64F, 0x1D400...0x1D44F,
        ]
        return ranges.map { $0.compactMap(Unicode.Scalar.init) }
    }()

    /// `target` bytes at most, in one or several scripts, spaces included.
    private static func value(_ random: inout QrRandom, target: Int) -> String {
        let mixed = Bool.random(using: &random)
        let single = pools.randomElement(using: &random) ?? []
        var out = String.UnicodeScalarView()
        var size = 0
        while size < target {
            let pool = mixed ? (pools.randomElement(using: &random) ?? []) : single
            guard let scalar = pool.randomElement(using: &random), size + scalar.utf8.count <= target else { break }
            out.append(scalar)
            size += scalar.utf8.count
        }
        return out.isEmpty ? "a" : String(out)
    }

    /// A window with a draft open, to put values through.
    private func draft(_ folder: String) throws -> MainWindowModel {
        let window = try ParityDemo.window(folder)
        _ = try window.session.beginNew(vault: try #require(window.main?.vault.id), group: nil)
        return window
    }

    /// Hands the main actor on first: one large decode takes a second, and
    /// suites run side by side.
    private func read(_ session: Session, _ vault: UInt64, _ text: String) async throws -> QrRead.Payload {
        await Task.yield()
        _ = try session.setPassword(vault: vault, value: text)
        let shown = try session.qrShowDraft(vault: vault, field: "Password")
        session.qrRelease(vault: vault, ticket: shown.ticket)
        return try QrRead.payload(shown.symbol)
    }

    private func expectExact(_ session: Session, _ vault: UInt64, _ text: String, _ note: String) async throws {
        let got = try await read(session, vault, text)
        #expect(got.eci == 26, "\(note)")
        #expect(got.bytes == Data(text.utf8), "\(note): \(text.utf8.count) bytes")
    }

    private func expectTooLarge(_ session: Session, _ vault: UInt64, _ text: String, _ note: String) async throws {
        await Task.yield()
        _ = try session.setPassword(vault: vault, value: text)
        #expect(throws: LarsalError.self, "\(note)") { try session.qrShowDraft(vault: vault, field: "Password") }
        do {
            _ = try session.qrShowDraft(vault: vault, field: "Password")
        } catch {
            #expect(message(error).hasPrefix("This value is too large for one QR code."), "\(note)")
        }
    }

    @Test("QR-T31 LD-359: 1,000 fitting random demo values read back exactly; only exact ones count")
    func thousandReadbacks() async throws {
        let window = try draft("qr-readback-1000")
        defer { window.lockAll() }
        let (session, vault) = (window.session, try #require(window.main?.vault.id))
        var random = QrRandom(state: 0x5152_2D54_3331)
        var exact = 0
        var scripts = Set<Int>()
        var generated = 0
        var longest = [false: 0, true: 0]
        for round in 0..<1_000 {
            // Most short, so the run stays short; the long end is always walked.
            let size =
                switch round % 20 {
                case 0: Int.random(in: 800...1_272, using: &random)
                case 1...4: Int.random(in: 200...800, using: &random)
                default: Int.random(in: 1...200, using: &random)
                }
            // One in ten comes from the generator: passwords, then phrases, in
            // each case mode; one in four of those at the UI's 999 and 100 words.
            let text: String
            if round % 10 == 7 {
                let long = round / 10 % 8 < 2
                let options = qrGenerated(round: round, size: long ? 1_200 : size)
                text = session.generate(options: options).value
                generated += 1
                let count = options.passphrase ? text.split(separator: " ").count : text.utf8.count
                if count == (options.passphrase ? 100 : 999) { longest[options.passphrase, default: 0] += 1 }
            } else {
                text = Self.value(&random, target: size)
            }
            let got = try await read(session, vault, text)
            if got.eci == 26, got.bytes == Data(text.utf8) {
                exact += 1
            } else {
                Issue.record("round \(round): \(text.utf8.count) bytes read back different")
            }
            scripts.formUnion(text.unicodeScalars.prefix(40).map { $0.utf8.count })
        }
        #expect(exact == 1_000)
        #expect(generated == 100, "generated values count among the 1,000")
        #expect(longest[false, default: 0] >= 5 && longest[true, default: 0] >= 5, "the longest too: \(longest)")
        #expect(scripts == [1, 2, 3, 4], "ASCII and two-, three- and four-byte scalars were all walked")
    }

    @Test("QR-T31 FEA-10.24: UI maxima: 999 ASCII and 999-byte phrases read back; oversize refuses")
    func uiMaxima() async throws {
        let window = try draft("qr-readback-ui")
        defer { window.lockAll() }
        let (session, vault) = (window.session, try #require(window.main?.vault.id))
        var options = GeneratorOptions(
            passphrase: false, length: 999, upper: true, lower: true, digits: true, special: true, extended: false,
            excludeLookalike: true, everyGroup: true, words: 100, separator: " ", case: .lower)
        let ascii = session.generate(options: options).value
        #expect(ascii.utf8.count == 999)
        try await expectExact(session, vault, ascii, "999 ASCII")
        // Extended-only is the UI's multi-byte class: 1,998 bytes.
        options.upper = false
        options.lower = false
        options.digits = false
        options.special = false
        options.extended = true
        options.excludeLookalike = false
        let extended = session.generate(options: options).value
        #expect(extended.utf8.count == 1_998)
        try await expectTooLarge(session, vault, extended, "999 extended")
        // Phrases: every case mode at 100 words, one space; each fits.
        options.passphrase = true
        for mode in [WordCase.lower, .upper, .title, .mixed] {
            options.case = mode
            let phrase = session.generate(options: options).value
            #expect(phrase.utf8.count <= 999)
            try await expectExact(session, vault, phrase, "100 words, \(mode)")
        }
        // The longest built-in phrase: 100 of the list's nine-byte words.
        let list = try String(
            contentsOf: ParityDemo.root.appending(path: "crates/larsal-core/src/generator/eff_large_wordlist.txt"),
            encoding: .utf8)
        let nine = list.split(separator: "\n").compactMap { $0.split(whereSeparator: \.isWhitespace).last }
            .filter { $0.utf8.count == 9 }
        var random = QrRandom(state: 999)
        let longest = (0..<100).map { _ in String(nine.randomElement(using: &random) ?? "") }.joined(separator: " ")
        #expect(longest.utf8.count == 999)
        try await expectExact(session, vault, longest, "999-byte phrase")
        // The maximum separators, ASCII and four-byte: 6,336 and 25,344 bytes alone.
        options.case = .lower
        options.separator = String(repeating: "-", count: 64)
        try await expectTooLarge(session, vault, session.generate(options: options).value, "64 ASCII")
        options.separator = String(repeating: "\u{1F600}", count: 64)
        let wide = session.generate(options: options).value
        #expect(wide.utf8.count > 25_344)
        try await expectTooLarge(session, vault, wide, "64 four-byte")
        // A long separator that still fits decodes: nothing is cut.
        options.words = 3
        try await expectExact(session, vault, session.generate(options: options).value, "64 four-byte, 3 words")
    }

    @Test("QR-T31 FEA-10.24: fitting custom-list shapes and case expansion read back; over refuses")
    func customListShapes() async throws {
        let window = try draft("qr-readback-list")
        defer { window.lockAll() }
        let (session, vault) = (window.session, try #require(window.main?.vault.id))
        // 256-scalar words: four and three spaces fit, five do not.
        let word = String(repeating: "w", count: 256)
        let four = Array(repeating: word, count: 4).joined(separator: " ")
        try await expectExact(session, vault, four, "four maximal words")
        try await expectTooLarge(session, vault, Array(repeating: word, count: 5).joined(separator: " "), "five")
        // U+0390 upper-cases to three scalars, six bytes; lower-case U+0130 to three bytes.
        let upper = String("\u{390}").uppercased()
        #expect(upper.utf8.count == 6)
        let uppers = Array(repeating: upper, count: 100).joined(separator: " ")
        try await expectExact(session, vault, uppers, "U+0390, 100 words")
        let lower = String("\u{130}").lowercased()
        #expect(lower.utf8.count == 3)
        let lowers = Array(repeating: lower, count: 100).joined(separator: " ")
        try await expectExact(session, vault, lowers, "U+0130, 100 words")
    }

    @Test("QR-T05 FEA-10.9: 1,272 reads back, 1,273 refuses: draft, saved placeholder, Wi-Fi wire")
    func exactCapacity() async throws {
        let window = try draft("qr-readback-1272")
        defer { window.lockAll() }
        let (session, vault) = (window.session, try #require(window.main?.vault.id))
        try await expectExact(session, vault, String(repeating: "a", count: 1_272), "literal draft, exact full")
        try await expectExact(session, vault, String(repeating: "\u{1F600}", count: 318), "four-byte, exact full")
        try await expectTooLarge(session, vault, String(repeating: "a", count: 1_273), "literal draft")
        try session.cancelEdit(vault: vault)
        // A short field whose resolution reaches the size.
        let name = String(repeating: "u", count: 1_272)
        let id = try QrDemo.entry(session, vault, [("Title", "T05"), ("UserName", name), ("Password", "{USERNAME}")])
        await Task.yield()
        let got = try QrRead.payload(try session.qrShowField(vault: vault, entry: id, field: "Password").symbol)
        #expect(got.bytes == Data(name.utf8) && got.eci == 26)
        let over = try QrDemo.entry(
            session, vault, [("Title", "T05"), ("UserName", name + "u"), ("Password", "{USERNAME}")])
        #expect(throws: LarsalError.self) { try session.qrShowField(vault: vault, entry: over, field: "Password") }
        // The Wi-Fi wire: S and P wrappers or all five escapes, Unicode, delimiters.
        let password = #"\;,":é"# + String(repeating: "a", count: 1_228)
        let wifi = try QrDemo.entry(
            session, vault, [("Title", "Wi-Fi"), ("UserName", "ABCD"), ("Password", password), ("Security", "WPA")])
        await Task.yield()
        let wire = try QrRead.payload(try session.qrShowWifi(vault: vault, entry: wifi).symbol)
        let text = try #require(String(bytes: wire.bytes, encoding: .utf8))
        #expect(wire.bytes.count == 1_272 && wire.eci == 26)
        #expect(text.hasPrefix(#"WIFI:T:WPA;S:"ABCD";P:\\\;\,\"\:é"#) && text.hasSuffix(";H:false;;"))
        let long = try QrDemo.entry(
            session, vault,
            [("Title", "Wi-Fi"), ("UserName", "ABCD"), ("Password", password + "a"), ("Security", "WPA")])
        #expect(throws: LarsalError.self) { try session.qrShowWifi(vault: vault, entry: long) }
    }

    @Test("QR-T04 FEA-10.8: Unicode keeps its bytes: composed and decomposed stay apart")
    func unicode() async throws {
        let window = try draft("qr-readback-unicode")
        defer { window.lockAll() }
        let (session, vault) = (window.session, try #require(window.main?.vault.id))
        let values = [
            "caf\u{E9}", "cafe\u{301}", "كلمة السر", "秘密の言葉", "\u{1F600}", "\u{1F469}\u{200D}\u{1F4BB}",
            "\u{1D400}\u{1D401}", "abc कखग كلمة 秘密 \u{1F600}",
        ]
        for value in values { try await expectExact(session, vault, value, "script") }
        let composed = try await read(session, vault, values[0])
        let decomposed = try await read(session, vault, values[1])
        #expect(composed.bytes != decomposed.bytes)
    }

    @Test("QR-T03 FEA-10.3: saved resolves, draft is literal; whitespace and control bytes stay")
    func showResult() async throws {
        let window = try draft("qr-readback-show")
        defer { window.lockAll() }
        let (session, vault) = (window.session, try #require(window.main?.vault.id))
        for value in [" ", "\t", "\r\n", "\n", "a\u{0}b", "https://demo.example/<b>&x=1", "  demo  "] {
            try await expectExact(session, vault, value, "bytes")
        }
        try session.cancelEdit(vault: vault)
        let id = try QrDemo.entry(
            session, vault, [("Title", "T03"), ("UserName", "demo-user"), ("Password", "{USERNAME}")])
        let saved = try session.qrShowField(vault: vault, entry: id, field: "Password")
        #expect(try QrRead.payload(saved.symbol).bytes == Data("demo-user".utf8))
        _ = try session.beginEdit(vault: vault, entry: id)
        let draft = try session.qrShowDraft(vault: vault, field: "Password")
        #expect(try QrRead.payload(draft.symbol).bytes == Data("{USERNAME}".utf8))
        try session.cancelEdit(vault: vault)
    }

    @Test("QR-T07 QR-T08 QR-T09 QR-T10 E21-S2: a join code reads back with its fields")
    func wifiReadback() throws {
        let window = try ParityDemo.window("qr-readback-wifi")
        defer { window.lockAll() }
        let (session, vault) = (window.session, try #require(window.main?.vault.id))
        func join(_ extra: [(String, String)]) throws -> [String: String] {
            let id = try QrDemo.entry(session, vault, [("Title", "Wi-Fi")] + extra)
            let wire = try QrRead.payload(try session.qrShowWifi(vault: vault, entry: id).symbol)
            #expect(wire.eci == 26)
            return fields(try #require(String(bytes: wire.bytes, encoding: .utf8)))
        }
        let base = [("UserName", "Demo Net"), ("Password", "demo-pass"), ("Security", "WPA2 Personal")]
        #expect(try join(base) == ["T": "WPA", "S": "Demo Net", "P": "demo-pass", "H": "false"])
        #expect(try join(base + [("Hidden", "true")])["H"] == "true")
        let hard = try join([("UserName", "Demo;Net"), ("Password", #"a\b:c,d"e;f"#), ("Security", "WPA")])
        #expect(hard["S"] == "Demo;Net" && hard["P"] == #"a\b:c,d"e;f"#)
        let hex = try join([("UserName", "ABCD"), ("Password", "1234"), ("Security", "WEP")])
        #expect(hex == ["T": "WEP", "S": "wrapped:ABCD", "P": "wrapped:1234", "H": "false"])
        let odd = try join([("UserName", "ABC"), ("Password", "123"), ("Security", "WPA")])
        #expect(odd["S"] == "ABC" && odd["P"] == "123")
        let open = try join([("UserName", "Caf\u{E9} 5G"), ("Password", "stale"), ("Security", "Open")])
        #expect(open == ["T": "nopass", "S": "Caf\u{E9} 5G", "H": "false"])
    }

    @Test("QR-T13 FEA-10.7: the one-time code's QR stays H and byte-only, with no ECI")
    func otpUnchanged() throws {
        let window = try ParityDemo.window("qr-readback-otp")
        defer { window.lockAll() }
        let main = try #require(window.main)
        main.edit(try #require(main.rows.first { $0.title == "GitHub" }?.id))
        let got = try QrRead.payload(try window.session.totpQr(vault: main.vault.id))
        #expect(got.eci == nil)
        #expect(String(bytes: got.bytes, encoding: .utf8)?.hasPrefix("otpauth://totp/") == true)
        main.closeEditor()
    }
}

/// One generated value's options: a password up to the UI's 999, or a phrase up
/// to 100 words, in each case mode by turn. A `size` of 1,200 or more is the longest.
private func qrGenerated(round: Int, size: Int) -> GeneratorOptions {
    GeneratorOptions(
        passphrase: round % 20 == 17, length: UInt32(min(size, 999)), upper: true, lower: true, digits: true,
        special: true, extended: false, excludeLookalike: false, everyGroup: false,
        words: UInt32(max(3, min(size / 12, 100))), separator: " ",
        case: [WordCase.lower, .upper, .title, .mixed][round / 20 % 4])
}

/// The fields of a join text, parsed as its format says: `\` escapes one
/// character, `;` ends a field, and S and P may hold outer quotes.
private func fields(_ wire: String) -> [String: String] {
    var out: [String: String] = [:]
    var rest = Substring(wire.dropFirst("WIFI:".count))
    while let colon = rest.firstIndex(of: ":") {
        let key = String(rest[..<colon])
        rest = rest[rest.index(after: colon)...]
        var value = ""
        var quoted = false
        while let char = rest.popFirst(), char != ";" {
            if char == "\\", let next = rest.popFirst() {
                value.append(next)
            } else if char == "\"" {
                quoted = true
            } else {
                value.append(char)
            }
        }
        out[key] = quoted ? "wrapped:" + value : value
    }
    return out
}
