import SwiftUI

/// The clock the screens read. Snapshot tests set the mockup's "now"
/// (2026-10-27 10:30) so dates read as drawn.
enum Clock {
    static var now: () -> Date = { Date() }
}

/// The mockup's date, time and size formats (mockup.js `fmtMod`, `fmtDay`,
/// `fmtTime`, month headers), in English and the Mac's time zone.
enum Formats {
    private static let calendar: Calendar = {
        var calendar = Calendar(identifier: .gregorian)
        calendar.locale = Locale(identifier: "en_US_POSIX")
        return calendar
    }()

    static func date(_ unix: Int64) -> Date { Date(timeIntervalSince1970: TimeInterval(unix)) }

    /// One formatter per pattern: making one is slow.
    private static var formatters: [String: DateFormatter] = [:]

    private static func text(_ date: Date, _ pattern: String) -> String {
        if let formatter = formatters[pattern] { return formatter.string(from: date) }
        let formatter = DateFormatter()
        formatter.calendar = calendar
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.dateFormat = pattern
        formatters[pattern] = formatter
        return formatter.string(from: date)
    }

    private static func sameYear(_ date: Date) -> Bool {
        calendar.component(.year, from: date) == calendar.component(.year, from: Clock.now())
    }

    /// "Today", "Yesterday", "5 days", "Oct 20", or "Oct 20, 2025".
    static func modified(_ unix: Int64) -> String {
        let date = date(unix)
        let days =
            calendar.dateComponents(
                [.day], from: calendar.startOfDay(for: date), to: calendar.startOfDay(for: Clock.now())
            ).day ?? 0
        switch days {
        case 0: return "Today"
        case 1: return "Yesterday"
        case 2..<7: return "\(days) days"
        default: return sameYear(date) ? day(unix) : text(date, "MMM d, yyyy")
        }
    }

    /// "Oct 22".
    static func day(_ unix: Int64) -> String { text(date(unix), "MMM d") }

    /// "08:49".
    static func time(_ unix: Int64) -> String { text(date(unix), "HH:mm") }

    /// A month header: "October", or "May 2025" in another year.
    static func month(_ unix: Int64) -> String {
        let date = date(unix)
        return sameYear(date) ? text(date, "MMMM") : text(date, "MMMM yyyy")
    }

    /// The month that holds `unix`, for grouping rows by month.
    static func monthOf(_ unix: Int64) -> DateInterval? { calendar.dateInterval(of: .month, for: date(unix)) }

    /// "created just now", "created today", "created Oct 18".
    static func created(_ unix: Int64) -> String {
        let date = date(unix)
        if Clock.now().timeIntervalSince(date) < 60 { return "created just now" }
        if calendar.isDate(date, inSameDayAs: Clock.now()) { return "created today" }
        return "created " + (sameYear(date) ? day(unix) : text(date, "MMM d, yyyy"))
    }

    /// "Mar 3, 2024, 10:12" (the editor's Properties and History).
    static func dateTime(_ unix: Int64) -> String { text(date(unix), "MMM d, yyyy, HH:mm") }

    /// "Jan 27, 2027".
    static func longDate(_ unix: Int64) -> String { text(date(unix), "MMM d, yyyy") }

    /// "Jun 3, 2026 at 11:20" (the earlier version's title).
    static func dateAt(_ unix: Int64) -> String { text(date(unix), "MMM d, yyyy 'at' HH:mm") }

    /// "Today, 09:12", else as `dateTime`.
    static func used(_ unix: Int64) -> String {
        calendar.isDate(date(unix), inSameDayAs: Clock.now()) ? "Today, " + time(unix) : dateTime(unix)
    }

    /// "464 B", "1.2 KB", "3.4 MB".
    static func size(_ bytes: UInt64) -> String {
        if bytes < 1000 { return "\(bytes) B" }
        let units = ["KB", "MB", "GB"]
        var value = Double(bytes) / 1024
        var unit = 0
        while value >= 1000, unit < units.count - 1 {
            value /= 1024
            unit += 1
        }
        return String(format: "%.1f %@", value, units[unit])
    }

    /// "1 entry", "23 entries".
    static func count(_ number: Int, _ one: String, _ many: String) -> String {
        "\(number) \(number == 1 ? one : many)"
    }
}

/// One-time codes on screen: FEA-04.15's display space drawn as the
/// mockup's thin space (U+2009), in the same text run as the digits, so the
/// code keeps IBM Plex Mono 500.
enum Codes {
    static func shown(_ code: String) -> String { code.replacingOccurrences(of: " ", with: "\u{2009}") }
}
