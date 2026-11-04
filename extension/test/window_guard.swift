// Rule 10 guard for test runs (AGENTS.md). Every 50 ms it reads the on-screen
// window list and the frontmost app; when either belongs to ROOT or a process
// under it, it stops that process by its PID and prints "window PID" or
// "front PID". It reads, and stops only processes under ROOT.
// Usage: window_guard ROOT [--dry-run]   (--dry-run reports and stops nothing)
// Prints "ready FRONT SELF" after its first look (SELF: whether the guard itself
// is under ROOT), and "done FRONT LOOKS" when stdin closes.
import AppKit

/// Writes one line to stdout at once (no buffer): the driver reads these lines.
func say(_ line: String) { FileHandle.standardOutput.write(Data((line + "\n").utf8)) }

let root = pid_t(CommandLine.arguments[1])!
let dryRun = CommandLine.arguments.contains("--dry-run")
if !dryRun && root <= 1 {
    say("refused: root \(root) is above every process")
    exit(2)
}
var seen = Set<String>()
var looks = 0

func under(_ pid: pid_t) -> Bool {
    var ancestor = pid
    while ancestor > 1 && ancestor != root {
        var info = kinfo_proc()
        var size = MemoryLayout<kinfo_proc>.stride
        var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_PID, ancestor]
        guard sysctl(&mib, 4, &info, &size, nil, 0) == 0, size > 0 else { return false }
        ancestor = info.kp_eproc.e_ppid
    }
    return ancestor == root
}

func front() -> pid_t { NSWorkspace.shared.frontmostApplication?.processIdentifier ?? 0 }

func hit(_ kind: String, _ pid: pid_t) {
    if !dryRun && pid > 1 { kill(pid, SIGKILL) }
    if seen.insert("\(kind) \(pid)").inserted { say("\(kind) \(pid)") }
}

func look() {
    looks += 1
    let windows = CGWindowListCopyWindowInfo(.optionOnScreenOnly, kCGNullWindowID) as? [[String: Any]] ?? []
    for window in windows {
        if let pid = window[kCGWindowOwnerPID as String] as? pid_t, under(pid) { hit("window", pid) }
    }
    let frontmost = front()
    if under(frontmost) { hit("front", frontmost) }
}

look()
say("ready \(front()) \(under(getpid()))")
Timer.scheduledTimer(withTimeInterval: 0.05, repeats: true) { _ in look() }
FileHandle.standardInput.readabilityHandler = { handle in
    if handle.availableData.isEmpty {
        DispatchQueue.main.async {
            say("done \(front()) \(looks)")
            exit(0)
        }
    }
}
RunLoop.main.run()
