"""Test driver for a test browser, headless (story E7-S7b, research B11).

Python standard library only. It starts only the pinned test browser:
$LARSAL_TEST_CHROME, the absolute path of a private open-source Chromium build
under TEST_BROWSERS, whose MANIFEST.json in a folder above it is the pinned one
(MANIFEST_SHA256: a manifest never vouches for itself) and records it with its
SHA-256, with every other file and link of its app (checked before each start).
With the variable unset, or a path anywhere else (/Applications included), it
refuses and starts nothing. It runs it with
--headless=new and the DevTools protocol over --remote-debugging-pipe, a
throwaway profile and a test HOME under /tmp, loads an unpacked extension with
Extensions.loadUnpacked, opens pages, runs scripts, takes screenshots and stops
the browser by its PID. It also runs the test sites every later story uses:
site-a.test, site-b.test and sub.site-a.test on an https demo server at
127.0.0.1, with a certificate made for the run.

Owner safety, checked on every run:
- the profile is <test HOME>/Library/Application Support/Google/Chrome
  (LD-274 (7)), so the native messaging folder Larsal writes under the test HOME
  (INT-01.8) is the one the browser reads; the test HOME is a folder under /tmp,
  inside a run root that is itself a folder under /tmp (the folder that holds it),
  and that root must be one this driver process made (run_root, or its own run
  folder) or one that holds this process's run marker (mark_root): any other
  folder under /tmp, another agent's included, is refused before anything starts;
- only the test flags in TEST_FLAGS, each with its reason, may be added to a
  start; any other flag (a helper's or launcher's path, a command prefix) is
  refused before anything starts;
- every run is inside the driver's sandbox (sandbox-exec, LD-285), which holds:
  writes: an allow-list. They are denied everywhere except under the run's own
  folders, the driver's run folder (the browser's TMPDIR and log, and the
  default test HOME) and the run root that holds the test HOME (the HOME with
  the profile, the crash database and the caches, and the test's own files
  beside it), and to the device file /dev/null. So no owner folder can be left
  out: /opt/homebrew, /usr/local, /Users/Shared, /Applications, /Library, the
  owner's home and per-user folders and /private/tmp itself are all denied;
  network: out only over TCP, on the demo server's port, to the addresses the
  sandbox calls "localhost" (none at all in a run without the demo server); no
  UDP; no unix-domain socket outside the run's own folders, to connect to or to
  bind (the system resolver's, syslog's and every other system socket
  included); and no bind or listen on any IP address. The sandbox language
  names a host only as "*" or "localhost"; under the "ip" form "localhost" was
  every address of this Mac and fe80::1 on any interface (round 3, UDP probes;
  it ignores the zone). Under "tcp" only 127.0.0.1 and ::1 (which work) and
  ::ffff:127.0.0.1 (refused) were tried; TCP to an address this Mac does not
  hold is never tried. So "127.0.0.1 and ::1 only" cannot be written there:
  the resolver rules and the socket check below hold the rest;
  services: no lookup of those that would write or ask for the owner
  (preferences, LaunchServices, privacy prompts, the clipboard, Apple events,
  the password and Touch ID agents (authd, the security agents and their
  authorization hosts, SecurityServer, securityd, CryptoTokenKit's token
  client, CoreAuthentication, LocalAuthentication, biometrickitd), the menu
  bar's status items, location registration, Handoff, notifications with their
  alerts and banners, distributed notifications, the passkey and credential
  sheets of AuthenticationServices, macOS's own web browser's launch agent,
  Spotlight's index agent, app shortcuts, Quick Note's backlinks and the Dock's
  full-screen service); the names com.apple.SecurityAgent and com.openssh.ssh-agent
  are not published on this Mac, so denying them walls nothing here: ssh-agent's
  socket is walled as a unix-domain socket outside the run's folders;
  macOS refuses a second sandbox inside one, so the browser's own sandbox is
  off (--no-sandbox) and its helpers run in the driver's; each run asks macOS
  (sandbox_check) that the live browser is inside it, and close() also lists
  the sockets of every process of the run (lsof) while it runs and fails on any
  internet socket whose address is not 127.0.0.1 or ::1, one on every interface
  ("*:port") included, and on any named unix-domain socket outside the run's own
  folders (lsof names a socket by the path it is bound to; a client shows only
  its peer's address, so connects are held by the sandbox);
- the browser and every helper the driver starts (the window guard and its
  compile) get LARSAL_TEST_INSTANCE_DIR, a run folder, so a debug larsal-bridge
  started under them never falls back to the owner's per-user temp folder;
- every start keeps a NetLog in the driver's run folder (or where the test's
  --log-net-log puts it); when a start or a page load fails, that start's
  socket connect events (addresses and ports) are kept in a new folder under
  /tmp, named in the error, and written again at close() when the NetLog is
  whole; and a fresh process under the run's own sandbox profile tries TCP to
  the demo server on 127.0.0.1, the error saying whether the profile refused
  it too (round 4: a rule order that refused about one port in ten showed so);
- every process of the run joins RUN_PIDS as it appears (the owner watch lists
  them every 0.5 s), so the log checks below match a helper that exits early
  (one that lives less than half a second, between two looks, can be missed);
- a crash report of the browser in macOS's report folder since the suite's
  first start fails the run; when the browser died by a signal the driver did
  not send, close() waits for the report macOS writes seconds later, and the
  death alone fails the run too; a new dump in the browser's own crash
  database fails it as well, and is kept in a folder under /tmp before the
  test HOME is removed; after the suite's last close, check_run_end waits for
  a late report again when any run died or left a dump;
- --use-mock-keychain: Chrome never writes to the owner's login keychain;
- --host-resolver-rules map only the three test names to 127.0.0.1 and every
  other name, an IP address too, to ~NOTFOUND, and --no-proxy-server keeps a
  system proxy out, so no test reaches the internet; the profile turns off the DNS error page's
  probe, and --disable-updater-scheduler keeps Chrome's updater from starting
  (each has its own resolver or network access); an updater found in the test
  HOME fails the run;
- --disable-features=MacAppCodeSignClone keeps Chrome from copying its app into
  the owner's temp folder at each start; that folder is watched too;
- --disable-features=OmniboxEverywhere keeps the browser from asking
  ControlCenter for a status item in the owner's menu bar (rule 10): the
  test browser's own field trial testing config turns that feature on, and
  with it the browser looked up com.apple.controlcenter.statusitems about 1.3
  to 2 s after each start (round 2, 2026-11-12: 3 of 3 starts with it, 0 of 1
  with the feature off, 0 of 1 with --disable-field-trial-config); the sandbox
  denies that lookup too;
- no path the driver writes under the test HOME goes through a link, so a
  test HOME cannot point Chrome or the echo host at the owner's Library;
- the test certificate is trusted only by this profile, through
  --ignore-certificate-errors-spki-list; nothing is added to a keychain;
- window_guard.swift (rule 10) watches the on-screen window list and the
  frontmost app, and stops at once any process of ours that shows a window or
  takes focus; when the guard itself stops early, Chrome is stopped too; a
  change of the frontmost app fails the run only when the frontmost app is a
  process of the run (a PID pids() returned at any look); the owner switching
  between their own apps is noted (FRONT_NOTES, stderr), not failed; the guard
  is compiled by the toolchain's swiftc called by its full path with SDKROOT
  (no xcrun, no xcodebuild: nothing that keeps a cache in the owner's per-user
  T or C folders), inside the driver's sandbox for the guard's own folder under
  /tmp, where its module caches are;
- the echo host runs under the suites' own interpreter, named by its full path,
  not /usr/bin/python3 (an xcrun shim); no DEVELOPER_DIR reaches the browser;
- the modification times of the owner's Chrome and Chromium files are read
  (stat only) before, every 0.5 s while it runs, and after; any change stops
  the browser at once and fails the run;
- the owner's login keychain is checked by process, not by its modification
  time, which macOS's own services change about every 10 minutes (LD-276): each
  run confirms --use-mock-keychain on the live Chrome's command line, and after
  a suite run macOS's own log shows no keychain write by a PID of the run
  (keychain_log and keychain_commits, read only); a run during which the
  system clock was changed cannot be checked that way and must run again;
- after a suite run, check_run_end also reads macOS's log for a menu bar item,
  a location registration or a Handoff activity of the run (ControlCenter,
  locationd, CoreLocationAgent and useractivityd lines naming a PID of the run,
  or ControlCenter lines naming the browser's bundle id: service_log,
  service_rows), and names the owner's ByHost preferences that
  changed with it; a ByHost change with no such line is the owner's own and is
  only noted. The driver watches only these paths, services and lines: a
  write it does not watch is not ruled out by a passing run.
"""

import atexit
import base64
import ctypes
import fcntl
import hashlib
import http.server
import json
import os
import plistlib
import pwd
import re
import secrets
import shutil
import signal
import ssl
import subprocess
import sys
import tempfile
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
TEST_CHROME = "LARSAL_TEST_CHROME"  # the absolute path of the pinned test browser's binary; no fallback
MANIFEST = "MANIFEST.json"  # in a folder above that binary: {"binary": {"path": <from that folder>, "sha256": ...}}
PROFILE = "Library/Application Support/Google/Chrome"  # under the test HOME, LD-274 (7)
NATIVE_HOSTS = "Library/Application Support/Google/Chrome/NativeMessagingHosts"  # INT-01.8
HOSTS = ("site-a.test", "site-b.test", "sub.site-a.test")  # .test is reserved, RFC 6761
RESOLVER_RULES = ", ".join(["MAP %s 127.0.0.1" % h for h in HOSTS] + ["MAP * ~NOTFOUND"])
REAL_HOME = pwd.getpwuid(os.getuid()).pw_dir  # never $HOME: it may be a test HOME
# The only place a test browser is started from (LD-428), and the SHA-256 of the MANIFEST.json of the one there,
# Chromium revision 1742560 (written in round 1, 2026-11-12): pinned here, so a folder with a manifest of its own
# that matches its own files is still refused.
TEST_BROWSERS = os.path.join(REAL_HOME, "Documents", "Code", "larsal-checkpoints", "tools", "chromium")
MANIFEST_SHA256 = "d0dd177890e3b32a3af0e0de5a029ec5b5d2eea0179aef23e75f40044ccf791e"
DEVICES = ("/dev/null",)  # the only files outside the run's own folders a process of the run may write
USER_FOLDERS = os.path.dirname(os.confstr(65537).rstrip("/"))  # the owner's T, C and X (confstr 65537: T)
OWNER_PATHS = tuple(
    os.path.join(REAL_HOME, "Library", p)
    for p in (
        "Preferences/com.google.Chrome.plist",
        "Application Support/Google/Chrome",
        "Application Support/Google/Chrome/Default",
        "Application Support/Google/Chrome/Local State",
        "Google",
        "Caches/Google",
        # Chromium's own names for the same files (the test browser)
        "Preferences/org.chromium.Chromium.plist",
        "Application Support/Chromium",
        "Application Support/Chromium/Default",
        "Application Support/Chromium/Local State",
        "Caches/Chromium",
    )
) + tuple(  # each browser clones its app here for code signing, by its bundle id
    os.path.join(USER_FOLDERS, "X", name + ".code_sign_clone") for name in ("com.google.Chrome", "org.chromium.Chromium")
)
REPORTS = os.path.join(REAL_HOME, "Library", "Logs", "DiagnosticReports")  # macOS's crash reports (LD-289)
CRASH_NAMES = ("Google Chrome", "Chromium", "chrome_crashpad_handler")  # a report's name starts with its process
REPORT_WAIT = 60  # s; macOS wrote the test browser's crash reports 8 to 21 s after it died (2026-11-12)
SANDBOX = "/usr/bin/sandbox-exec"
# The window guard's compiler (C2R3-01): the toolchain's swiftc by its full path, with SDKROOT, so no xcrun and no
# xcodebuild run (libxcrun keeps its cache in the owner's T/xcrun_db, xcodebuild its plug-in cache in the owner's
# C/com.apple.DeveloperTools).
XCODE = "/Applications/Xcode.app/Contents/Developer"
SWIFTC = XCODE + "/Toolchains/XcodeDefault.xctoolchain/usr/bin/swiftc"
SDK = XCODE + "/Platforms/MacOSX.platform/Developer/SDKs/MacOSX.sdk"
# The only flags a test may add to a start (C2R3-06), each with its reason. Anything else, a flag that names a
# program or a command prefix (--browser-subprocess-path, --renderer-cmd-prefix, ...) or an unknown one, is refused.
TEST_FLAGS = {
    "--log-net-log": "the start's NetLog at a path the test reads after close (the DNS error page test); the write "
                     "allow-list keeps it in the run's own folders",
    "--net-log-capture-mode": "how much that NetLog keeps (the DNS error page test asks for Everything)",
}
# Services that act for a process outside its sandbox and reach the owner's things, denied as the project's
# guard profiles deny them: cfprefsd writes ~/Library/Preferences and lsd registers the app with LaunchServices
# (both seen in the test browser's first guarded run; the check-in with launchservicesd stays, without it the
# browser does not start), tccd asks for privacy rights, the pasteboard is the owner's clipboard (rule 10),
# Apple events reach the owner's apps, the security agents ask for a password or Touch ID, and ssh-agent holds
# the owner's keys. Round 2 (2026-11-12): ControlCenter's com.apple.controlcenter.statusitems put an item of
# the test browser in the owner's menu bar (rule 10; the browser logs "Alloc com.apple.controlcenter.statusitems"
# and ControlCenter "bid:org.chromium.Chromium-Item-0-<PID>"), and locationd's com.apple.locationd.desktop
# .registration, with CoreLocationAgent, registered the browser as a location client (macOS keeps that record);
# useractivityd (com.apple.coreservices.lsuseractivitymanager.xpc) made each start's activity its Handoff current
# item, which this Mac allows to be advertised to the owner's other devices; and the browser asks usernoted, which
# shows notifications on the owner's screen, at every start. Round 3 (Checker 2's C2-02 and C2-08): the other
# names that put a notification, an alert or a banner on the owner's screen (usernoted's and usernotificationsd's
# com.apple.usernotifications* names, UserNotificationCenter's alerts drawn by another process, NotificationCenter's
# UI, ControlCenter's SystemBanner and SystemBannerService), AuthenticationServicesAgent, which shows the passkey
# and credential sheets (the browser asked it at every start), and macOS's own web browser's launch agent (asked
# once per start). Round 4 (Checker 2's C2R3-03 and C2R3-04): every live name the browser asked, or that a password
# prompt would use, denied one at a time, each with a single start, then the suites: Spotlight's index agent (the
# browser sent it an index change), linkd's app shortcuts, Quick Note's backlinks, the Dock's full-screen service,
# distributed notifications, CryptoTokenKit's token client, authd, the security agents and their authorization
# host, SecurityServer and securityd. com.apple.SecurityAgent and com.openssh.ssh-agent are not published on this
# Mac (denying them walls nothing here; ssh-agent's launchd socket is walled as a unix socket).
SERVICES = ('(global-name "com.apple.cfprefsd.agent") (global-name-prefix "com.apple.lsd") '
            '(global-name-prefix "com.apple.tccd") '
            '(global-name-prefix "com.apple.pboard") (global-name-prefix "com.apple.pasteboard") '
            '(global-name-prefix "com.apple.coreservices.appleevents") (global-name "com.apple.SecurityAgent") '
            '(global-name-prefix "com.apple.CoreAuthentication") (global-name-prefix "com.apple.LocalAuthentication") '
            '(global-name "com.apple.biometrickitd") (global-name "com.openssh.ssh-agent") '
            '(global-name-prefix "com.apple.controlcenter.") (global-name-prefix "com.apple.locationd.") '
            '(global-name "com.apple.CoreLocation.agent") '
            '(global-name-prefix "com.apple.coreservices.lsuseractivity") (global-name-prefix "com.apple.usernoted.") '
            '(global-name-prefix "com.apple.usernotifications") (global-name "com.apple.UNCUserNotification") '
            '(global-name-prefix "com.apple.notificationcenterui.") (global-name-prefix "com.apple.SystemBanner") '
            '(global-name-prefix "com.apple.AuthenticationServices") (global-name "com.apple.SafariLaunchAgent") '
            '(global-name "com.apple.spotlight.IndexAgent") (global-name "com.apple.linkd.autoShortcut") '
            '(global-name "com.apple.synapse.backlink-service") (global-name "com.apple.dock.fullscreen") '
            '(global-name "com.apple.distributed_notifications@Uv3") (global-name "com.apple.ctkd.token-client") '
            '(global-name "com.apple.authd") (global-name "com.apple.security.agent") '
            '(global-name "com.apple.security.agent.login") (global-name "com.apple.security.authhost") '
            '(global-name "com.apple.SecurityServer") (global-name "com.apple.securityd.xpc")')
_SANDBOX_CHECK = ctypes.CDLL("/usr/lib/libSystem.B.dylib").sandbox_check
_SANDBOX_CHECK.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int]  # then the name, as a variadic argument
NO_REPORT = 0x40000000  # SANDBOX_CHECK_NO_REPORT: sandbox_check asks only, and the kernel logs no deny row (C2R3-07)
GLOBAL_NAME = 2  # sandbox_check's filter type for a global service name
# Round 4: TCP connect() to the demo server on 127.0.0.1 (the port in argv), after a failed page load (loopback_note).
LOOPBACK_PROBE = """import errno, socket, sys
s = socket.socket()
s.settimeout(2)
try:
    s.connect(("127.0.0.1", int(sys.argv[1])))
    print("connected")
except OSError as e:
    print(errno.errorcode.get(e.errno, str(e)))
"""
KEYCHAIN_LOG = 'subsystem == "com.apple.securityd" AND eventMessage CONTAINS "login.keychain-db"'
# ControlCenter puts an app's status item in the menu bar and logs it as "bid:<bundle id>-Item-0-<PID>";
# locationd and CoreLocationAgent log a location client's registration with its PID (round 2, F1 and F2), and
# useractivityd a Handoff current item as "... into the currentItem from process <private>/<PID>".
SERVICE_LOG = ('process == "ControlCenter" OR process == "locationd" OR process == "CoreLocationAgent" OR '
               'process == "useractivityd"')
BYHOST = os.path.join(REAL_HOME, "Library", "Preferences", "ByHost")  # ControlCenter rewrites its menu bar list here
# The browser's own crash databases in the test HOME: Chromium keeps its in the HOME, Chrome in the profile.
CRASH_DUMPS = ("Library/Application Support/Chromium/Crashpad", PROFILE + "/Crashpad")
RUN_PIDS = set()  # every PID of a Chrome run in this process, for keychain_commits (LD-276)
BUNDLES = set()  # the bundle id of each browser this process started, for service_rows
DEATHS = []  # each browser of this process that died by a signal the driver did not send, or left a crash dump
BYHOST_NOTES = []  # ByHost changes with no line of ours: the owner's own, recorded by check_run_end
FRONT_NOTES = []  # (before, after): changes of the frontmost app to no process of the run, the owner's own switches
ROOTS = set()  # the run roots this process made (run_root and each run's own folder), real paths (C1R3-06)
MARKER = ".larsal-run-root"  # in a root mark_root marked: this process's PID and TOKEN
TOKEN = secrets.token_hex(16)  # kept only in this process's memory
_HASHED = {}  # path: ((size, mtime, inode, ctime), SHA-256) of the test browser's files read by this process
_BASELINE = {}  # once per process (one suite): REPORTS folder: report names, and "byhost": ByHost times
# macOS's log is read by the clock, so a change of the system clock during a run (System Settings can set it
# back a day) hides that time's lines from keychain_log: the run's watch notes each change it sees.
CLOCK = time.time() - time.monotonic()
CLOCK_STEPS = []


class DriverError(Exception):
    pass


class OwnerFilesChanged(DriverError):
    pass


def check_test_home(path):
    """Returns the real path of a test HOME; refuses anything not under /tmp."""
    real = os.path.realpath(path)
    if not real.startswith("/private/tmp/"):
        raise DriverError("test HOME must be a folder under /tmp, not %s" % real)
    return real


def run_root(prefix="larsal-run-"):
    """A new folder under /tmp made by this driver process, for a test HOME and the test's own files beside it: a
    run root the driver accepts (C1R3-06)."""
    folder = tempfile.mkdtemp(prefix=prefix, dir="/tmp")
    ROOTS.add(os.path.realpath(folder))
    return folder


def mark_root(folder):
    """Writes this process's run marker (its PID and TOKEN) into `folder`, a folder of this user under /tmp made
    elsewhere, so the driver accepts it as a run root (C1R3-06)."""
    real = os.path.realpath(folder)
    if not real.startswith("/private/tmp/") or not os.path.isdir(real) or os.stat(real).st_uid != os.getuid():
        raise DriverError("only a folder of this user under /tmp can be marked as a run root, not %s" % real)
    with open(os.path.join(real, MARKER), "x") as f:
        f.write("%d %s\n" % (os.getpid(), TOKEN))


def check_run_root(root):
    """C1R3-06: the folder that holds a test HOME is one this process made (ROOTS) or marked (MARKER); any other
    folder under /tmp, another agent's root too, is refused before anything is written or started."""
    real = os.path.realpath(root)
    if real in ROOTS:
        return real
    try:
        with open(os.path.join(real, MARKER)) as f:
            if f.read() == "%d %s\n" % (os.getpid(), TOKEN):
                return real
    except OSError:
        pass
    raise DriverError("refused: %s was not made by this driver process (run_root) and holds no run marker of it "
                      "(mark_root)" % real)


def check_test_flags(args):
    """C2R3-06: a test may add only the flags in TEST_FLAGS; the driver's own flags and any other flag or argument
    are refused before anything starts. Chrome takes "-name" as "--name" and the last value wins, so names are
    compared without dashes."""
    names = {a.split("=", 1)[0].lstrip("-"): a for a in args}
    own = set(names) & {f.split("=", 1)[0].lstrip("-") for f in chrome_flags("-", "-")}
    if own:
        raise DriverError("these flags are the driver's own: " + ", ".join(sorted(own)))
    other = sorted(a for name, a in names.items() if "--" + name not in TEST_FLAGS)
    if other:
        raise DriverError("refused before the start: %s: not on the driver's list of test flags (TEST_FLAGS: %s)"
                          % (", ".join(other), ", ".join(sorted(TEST_FLAGS))))


def connects(path):
    """The socket connect events of a NetLog, whole or still being written (the constants, then one event per
    line): each event whose type names a CONNECT and whose parameters hold an address or an error."""
    with open(path, errors="replace") as f:
        text = f.read()
    try:
        data = json.loads(text)
        constants, events = data["constants"], data.get("events") or []
    except ValueError:
        start = re.search(r'"events"\s*:\s*\[', text)
        constants, events = json.loads(text[:start.start()].rstrip().rstrip(",") + "}")["constants"], []
        for line in text[start.end():].splitlines():
            try:
                events.append(json.loads(line.strip().rstrip(",")))
            except ValueError:
                pass  # the line being written, or the end of the list
    names = {number: name for name, number in constants["logEventTypes"].items()}
    found = []
    for event in events:
        name, params = names.get(event.get("type"), str(event.get("type"))), event.get("params") or {}
        if "CONNECT" in name and any("address" in key or key == "net_error" for key in params):
            found.append({"time": event.get("time"), "type": name, "phase": event.get("phase"),
                          "source": (event.get("source") or {}).get("id"), "params": params})
    return found


def inside(home, part):
    """home/part; refused when any part of it under `home` (a real path) is a link."""
    path = os.path.join(home, part)
    if os.path.realpath(path) != path:
        raise DriverError("%s goes through a link: the test HOME must hold no link on the driver's paths" % path)
    return path


def owner_times(paths=OWNER_PATHS):
    """Modification times of the owner's files (stat only; None when missing)."""
    times = {}
    for path in paths:
        try:
            times[path] = os.stat(path, follow_symlinks=False).st_mtime_ns
        except FileNotFoundError:
            times[path] = None
    return times


def check_owner_times(before):
    after = owner_times(tuple(before))
    changed = [p for p in before if after[p] != before[p]]
    if changed:
        raise OwnerFilesChanged("owner files changed during the run (stop and report): " + ", ".join(changed))


def crash_reports():
    """The names of the browser's crash reports in macOS's report folder (names only)."""
    try:
        return {name for name in os.listdir(REPORTS) if name.startswith(CRASH_NAMES)}
    except FileNotFoundError:
        return set()


def new_crash_reports():
    """F5: the browser's crash reports that appeared since this process's first look, one baseline per suite
    process, so a late report of an earlier run is never taken into a later start's baseline."""
    found = crash_reports()
    return sorted(found - _BASELINE.setdefault(REPORTS, found))


def crash_dumps(home):
    """F5: every file in the pending, completed and new folders of the browser's own crash databases in the
    test HOME (Crashpad writes a dump there before macOS writes its report, if it ever does)."""
    found = set()
    for database in CRASH_DUMPS:
        for part in ("pending", "completed", "new"):
            for parent, _, names in os.walk(os.path.join(home, database, part)):
                found.update(os.path.join(parent, name) for name in names)
    return found


def keep_dumps(home, dumps):
    """Copies crash dumps out of a test HOME that is about to be removed, into a new folder under /tmp, the
    driver's test root (never the owner's folders); returns that folder."""
    kept = tempfile.mkdtemp(prefix="larsal-crash-dumps-", dir="/tmp")
    for path in dumps:
        target = os.path.join(kept, os.path.relpath(path, home))
        os.makedirs(os.path.dirname(target), exist_ok=True)
        shutil.copy2(path, target)
    return kept


def byhost_times():
    """The modification time of each entry of the owner's ByHost preferences (stat only)."""
    times = {}
    try:
        names = os.listdir(BYHOST)
    except FileNotFoundError:
        return times
    for name in names:
        try:
            times[name] = os.stat(os.path.join(BYHOST, name), follow_symlinks=False).st_mtime_ns
        except FileNotFoundError:
            pass
    return times


def bundle_id(binary):
    """The bundle id in the Info.plist of the app that holds `binary`, or None (no app, no id)."""
    app = binary
    while not app.endswith(".app") and app != "/":
        app = os.path.dirname(app)
    try:
        with open(os.path.join(app, "Contents", "Info.plist"), "rb") as f:
            return plistlib.load(f).get("CFBundleIdentifier")
    except (OSError, ValueError, plistlib.InvalidFileException):
        return None


def file_sha256(path):
    """A file's SHA-256, kept for this process by its path, size, modification time, inode and change time, so
    each start re-reads only a file that changed since (F4)."""
    st = os.stat(path, follow_symlinks=False)
    key = (st.st_size, st.st_mtime_ns, st.st_ino, st.st_ctime_ns)
    if _HASHED.get(path, (None,))[0] != key:
        digest = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                digest.update(chunk)
        _HASHED[path] = (key, digest.hexdigest())
    return _HASHED[path][1]


def program_files(folder, manifest, binary):
    """F4: what differs between the test browser's app and its MANIFEST.json in `folder`: a file not named in
    "files" (path: SHA-256) with its SHA-256, a named file missing, and a link not named in "links" (path:
    target) with its target. The app is the ".app" folder that holds `binary` (else the binary's own folder):
    the launcher, the framework, its helpers and libraries, everything the running browser loads from it."""
    app = binary
    while not app.endswith(".app") and app != "/":
        app = os.path.dirname(app)
    if app == "/":
        app = os.path.dirname(binary)
    files, links = manifest.get("files") or {}, manifest.get("links") or {}
    top = os.path.relpath(app, folder) + "/"
    seen, differ = set(), []
    for parent, dirs, names in os.walk(app):
        for name in dirs + names:
            path = os.path.join(parent, name)
            rel = os.path.relpath(path, folder)
            if os.path.islink(path):
                seen.add(rel)
                if links.get(rel) != os.readlink(path):
                    differ.append(rel + " (link)")
            elif name in names:
                seen.add(rel)
                if files.get(rel) != file_sha256(path):
                    differ.append(rel)
    differ += [rel + " (missing)" for rel in sorted(set(files) | set(links)) if rel.startswith(top) and rel not in seen]
    return differ


def browser_binary(environ=os.environ):
    """The browser to start, and the only one: $LARSAL_TEST_CHROME, an absolute path under TEST_BROWSERS, when
    the MANIFEST.json of a folder above it (up to TEST_BROWSERS) is the pinned one (MANIFEST_SHA256) and names it
    with its SHA-256, and every other file and link of its app too (F4: the framework and the helpers that run
    are checked before each start, not only the launcher). With the variable unset, or any other path
    (/Applications included: the owner's own browsers stay untouched), it refuses (C2-12): no fallback."""
    path = environ.get(TEST_CHROME)
    if not path:
        raise DriverError("refused: %s is not set; the driver starts only the pinned test browser under %s"
                          % (TEST_CHROME, TEST_BROWSERS))
    if not os.path.isabs(path):
        raise DriverError("%s must be an absolute path, not %r" % (TEST_CHROME, path))
    real, tools = os.path.realpath(path), os.path.realpath(TEST_BROWSERS)
    if not real.startswith(tools + "/"):
        raise DriverError("refused: %s is not under %s, where the pinned test browser is" % (real, tools))
    folder = os.path.dirname(real)
    while not os.path.isfile(os.path.join(folder, MANIFEST)) and folder not in (tools, "/"):
        folder = os.path.dirname(folder)
    try:
        with open(os.path.join(folder, MANIFEST), "rb") as f:
            data = f.read()  # hashed and read from the same bytes
        if hashlib.sha256(data).hexdigest() != MANIFEST_SHA256:
            raise DriverError("refused: %s is not the pinned manifest (SHA-256 %s)"
                              % (os.path.join(folder, MANIFEST), MANIFEST_SHA256))
        manifest = json.loads(data)
        recorded = manifest["binary"]
        digest = file_sha256(real)
        known = os.path.join(folder, recorded["path"]) == real and recorded["sha256"] == digest
    except (OSError, ValueError, KeyError, TypeError) as e:
        raise DriverError("refused: %s: no %s above it names it (%s)" % (real, MANIFEST, e))
    if not known:
        raise DriverError("refused: %s (SHA-256 %s) is not the binary %s records"
                          % (real, digest, os.path.join(folder, MANIFEST)))
    differ = program_files(folder, manifest, real)
    if differ:
        raise DriverError("refused: the test browser's app differs from %s: %s%s"
                          % (os.path.join(folder, MANIFEST), ", ".join(differ[:10]),
                             " and %d more" % (len(differ) - 10) if len(differ) > 10 else ""))
    return real


def sandbox_profile(writable=(), ports=()):
    """The sandbox every run is inside (LD-285). Writes: denied everywhere but under the folders `writable` (the
    run's own) and to DEVICES, an allow-list (C2-01). Network: out only over TCP to "localhost" on `ports` (the demo
    server's), no UDP; no unix-domain socket outside `writable`, to connect to or to bind (C2R3-02), so not the
    system resolver's either; no bind or listen on any IP address. Lookups: none of SERVICES, which would write or
    ask for the owner."""
    # The sandbox matches real paths only (/tmp is a link to /private/tmp).
    writable = sorted({os.path.realpath(w) for w in writable})
    if any('"' in w or "\\" in w for w in writable):
        raise DriverError("a sandbox path cannot hold a quote or a backslash: %r" % (writable,))
    if any(type(p) is not int or not 0 < p < 65536 for p in ports):
        raise DriverError("a sandbox port must be a number from 1 to 65535: %r" % (ports,))
    # A host can only be "*" or "localhost" (sandbox-exec: "host must be * or localhost in network address"; it
    # refuses 127.0.0.1, [::1] and loopback as hosts too), and under "ip" "localhost" was every address of this Mac,
    # 0.0.0.0, :: and fe80::1 on any interface (round 3, UDP probes), so the rule narrows by protocol and port only:
    # "tcp" (C1R3-01; "tcp4" would refuse ::1, and "ip" let UDP out to every address it calls localhost);
    # ::ffff:127.0.0.1 is refused (round 4); the resolver rules and outside_loopback keep the browser on 127.0.0.1
    # and ::1. A local address is "*" or "localhost" too, so binding and listening are denied on every IP address,
    # loopback included: the browser needs none (DevTools runs over a pipe, the demo server is the driver's).
    # Unix-domain sockets: the kernel names their real paths to the sandbox (/tmp forms match too).
    folders = " ".join('(subpath "%s")' % w for w in writable)
    # The unix-socket lines come first and the IP lines after them, so for an IP socket the last rules that match
    # are always "deny remote ip" and the port's allow, and no unix-socket line can decide it. With the port's allow
    # before the unix-socket lines, the sandbox refused TCP on the allowed port for about one port in eight (26 of
    # 200, the same ports every time, whatever the folders: r4/probes/tcp-ports-1.json, tcp-profiles-1.json); that
    # was every refused page load of round 4 (svc-5's first try, extension-1's second).
    lines = ["(version 1)", "(allow default)", "(deny network-outbound (remote unix-socket))",
             "(deny network-bind (local unix-socket))"]
    # One allow for each folder: with two subpaths in one (remote unix-socket ...) the kernel let only the first
    # through (round 4: extension-1's bridge could not reach the stand-in Larsal in the run root; r4/probes/unix-two-1).
    lines += ['(allow network-outbound (remote unix-socket (subpath "%s")))' % w for w in writable]
    lines += ['(allow network-bind (local unix-socket (subpath "%s")))' % w for w in writable]
    lines += ["(deny network-outbound (remote ip))"]
    lines += ['(allow network-outbound (remote tcp "localhost:%d"))' % p for p in sorted(set(ports))]
    lines += ['(deny network-inbound (local ip "*:*"))', "(deny file-write*)"]
    lines += ["(allow file-write* %s)" % folders] if writable else []
    lines += ["(allow file-write* %s)" % " ".join('(literal "%s")' % d for d in DEVICES),
              "(deny mach-lookup %s)" % SERVICES]
    return "\n".join(lines) + "\n"


def sandboxed(argv, profile=None):
    """argv inside the sandbox: sandbox-exec applies it and execs argv[0], so the PID stays the same."""
    return [SANDBOX, "-p", profile or sandbox_profile()] + list(argv)


def denies_lookup(pid, name):
    """True when the sandbox of process `pid` denies the lookup of service `name` (sandbox_check only asks, and
    with NO_REPORT the kernel logs no deny row for it, so a log check never takes the question for a lookup)."""
    return _SANDBOX_CHECK(pid, b"mach-lookup", GLOBAL_NAME | NO_REPORT, name.encode()) == 1


def unix_sockets_outside(pids, folders):
    """C2R3-02: the named unix-domain sockets of `pids` (lsof -U, read only) outside the real paths `folders`. lsof
    names a socket by the path it is bound to; "->0x..." is an unnamed socket's peer, not a path."""
    rows = subprocess.run(["/usr/sbin/lsof", "-nP", "-a", "-U", "-p", ",".join(map(str, pids)), "-F", "n"],
                          capture_output=True, text=True).stdout.splitlines()
    names = [r[1:] for r in rows if r.startswith("n/")]
    real = [os.path.realpath(f) for f in folders]
    return [n for n in names if not any(os.path.realpath(n).startswith(f + "/") for f in real)]


def outside_loopback(pids):
    """Internet sockets of `pids` with an address that is not 127.0.0.1 or ::1 (lsof, read only), at either
    end: this Mac's other addresses, 0.0.0.0, :: and fe80::1 are outside too (the sandbox's "localhost" lets
    them through, C2-03). "*:port" listens on every interface, so it is outside; only "*:*", a socket with no
    address and no port yet, reaches nothing."""
    rows = subprocess.run(["/usr/sbin/lsof", "-nP", "-a", "-i", "-p", ",".join(map(str, pids)), "-F", "n"],
                          capture_output=True, text=True).stdout.splitlines()
    names = [r[1:] for r in rows if r.startswith("n")]
    local = re.compile(r"^(?:127\.0\.0\.1|\[::1\]):[0-9*]+$")
    return [n for n in names if n != "*:*" and not all(local.match(part) for part in n.split("->"))]


def command_line(pid):
    return subprocess.run(["/bin/ps", "-ww", "-o", "command=", "-p", str(pid)], capture_output=True,
                          text=True).stdout.strip()


def keychain_log(start, end):
    """securityd's lines that name a login.keychain-db between two time.time() values (read only)."""
    stamp = lambda t: time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(t))
    return subprocess.run(["/usr/bin/log", "show", "--start", stamp(int(start)), "--end", stamp(int(end) + 1),
                           "--predicate", KEYCHAIN_LOG, "--style", "compact"],
                          check=True, capture_output=True, text=True).stdout


def keychain_commits(log, pids):
    """The lines of keychain_log where a process in `pids` committed (securityd writes "commited") a
    keychain file. Compact style names the writer as "name[PID:TID]", and a name may have spaces."""
    found = []
    for line in log.splitlines():
        writer = re.search(r"\[(\d+):[0-9a-f]+\] ", line)
        if writer and int(writer.group(1)) in pids and " commited " in line:
            found.append(line)
    return found


def check_keychain_log(start):
    """LD-276, LD-278 (3): after a run that started at `start` (a time.time() value), macOS's own log
    shows no keychain write by a PID of the run (RUN_PIDS) or by this process. Every suite that starts
    Chrome or Larsal calls it once, after the run; a write stops the run with OwnerFilesChanged. When the
    system clock changed during the run, the log cannot be read for its window: DriverError, run again."""
    if CLOCK_STEPS or abs(time.time() - time.monotonic() - CLOCK) > 5:
        raise DriverError("the system clock was changed during the run, so macOS's log cannot show its keychain "
                          "writes (LD-276): run again")
    found = keychain_commits(keychain_log(start, time.time()), RUN_PIDS | {os.getpid()})
    if found:
        raise OwnerFilesChanged("STOP (LD-276): a process of this run wrote a keychain: " + "; ".join(found))


def service_log(start, end):
    """ControlCenter's, locationd's, CoreLocationAgent's and useractivityd's lines between two time.time() values (read only;
    macOS's log still holds these processes' lines, unlike the kernel's sandbox lines since 2026-11-12)."""
    stamp = lambda t: time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(t))
    return subprocess.run(["/usr/bin/log", "show", "--start", stamp(int(start)), "--end", stamp(int(end) + 1),
                           "--predicate", SERVICE_LOG, "--style", "compact"],
                          check=True, capture_output=True, text=True).stdout


UUID = re.compile(r"[0-9A-Fa-f]{8}(?:-[0-9A-Fa-f]{4}){3}-[0-9A-Fa-f]{12}")


def service_rows(log, pids, bundles=()):
    """The lines of service_log that show a menu bar item, a location client or a Handoff activity of the run
    (F1, F2): a ControlCenter line that names a PID in `pids` or a bundle id in `bundles`, or a locationd,
    CoreLocationAgent or useractivityd line that names a PID in `pids` ("Item-0-4242", "peer[4242]", "pid:4242",
    "<private>/4242": a number on its own, never part of a longer number, a hex id, a UUID or a decimal).
    Compact style: "<time> <type> name[PID:TID] text"."""
    found = []
    for line in log.splitlines():
        row = re.match(r"^\S+ \S+\s+\S+\s+(ControlCenter|locationd|CoreLocationAgent|useractivityd)\[\d+:[0-9a-f]+\] (.*)$",
                       line)
        if not row:
            continue
        process, text = row.groups()
        # Round 4 (starts30): a UUID's all-digit groups are no numbers. ControlCenter's Now Playing requests for the
        # owner's players ("resolvePlayerPath<219BFE0B-8298-4322-...>") named a PID of the run that way.
        text = UUID.sub(" ", text)
        numbers = {int(n) for n in re.findall(r"(?<![0-9A-Za-z.])[0-9]+(?![0-9A-Za-z.])", text)}
        if numbers & set(pids) or (process == "ControlCenter" and any(b in text for b in bundles)):
            found.append(line)
    return found


def check_run_end(start):
    """Every suite's last check, after its last close (tearDownModule), for the whole run since `start` (a
    time.time() value). All parts always run; any finding fails the suite:
    1. F5: when a browser of the run died by a signal the driver did not send, or left a crash dump, it first
       waits up to REPORT_WAIT s for macOS's report; a crash report of the browser that appeared since this
       process's first start fails the run (OwnerFilesChanged);
    2. F1, F2: a ControlCenter line that names a PID of the run (RUN_PIDS, this process) or the bundle id of a
       browser it started (an item in the owner's menu bar), or a locationd or CoreLocationAgent line that names
       a PID of the run (a location registration), fails the run (OwnerFilesChanged), with the owner's ByHost
       entries that changed; a ByHost change with no such line is the owner's own: noted on stderr and kept in
       BYHOST_NOTES, not a failure;
    3. check_keychain_log (LD-276).
    A change of the system clock during the run hides lines from 2 and 3: DriverError, run again."""
    problems, error = [], DriverError
    deadline = time.monotonic() + (REPORT_WAIT if DEATHS else 0)
    while True:  # macOS writes a crash report seconds after the crash
        reports = new_crash_reports()
        if reports or time.monotonic() >= deadline:
            break
        time.sleep(0.5)
    if reports:
        problems.append("the browser left crash reports in the owner's folder (stop and report): " + ", ".join(reports))
        error = OwnerFilesChanged
    before, after = _BASELINE.get("byhost"), byhost_times()
    byhost = sorted(n for n in set(before or ()) | set(after) if (before or {}).get(n) != after.get(n)) \
        if before is not None else []
    if CLOCK_STEPS or abs(time.time() - time.monotonic() - CLOCK) > 5:
        problems.append("the system clock was changed during the run, so macOS's log cannot show its lines: run again")
    else:
        rows = service_rows(service_log(start, time.time()), RUN_PIDS | {os.getpid()}, BUNDLES)
        if rows:
            problems.append("STOP (rule 10): macOS's log shows a menu bar item, a location registration or a Handoff "
                            "activity of the run"
                            "%s: %s" % (" (ByHost changed: %s)" % ", ".join(byhost) if byhost else "",
                                        "; ".join(rows[:5])))
            error = OwnerFilesChanged
        elif byhost:
            BYHOST_NOTES.append(byhost)
            print("note: the owner's ByHost preferences changed during the run with no ControlCenter line of ours "
                  "(the owner's own; recorded, not a failure): " + ", ".join(byhost), file=sys.stderr)
    try:
        check_keychain_log(start)
    except OwnerFilesChanged as e:
        problems.insert(0, str(e))
        error = OwnerFilesChanged
    except DriverError as e:
        problems.append(str(e))
    if problems:
        raise error("; ".join(problems))


_guard = []


def guard_binary():
    """Compiles window_guard.swift once per process into a folder under /tmp, with the toolchain's swiftc called by
    its full path and SDKROOT (C2R3-01, C1R3-02): no xcrun and no xcodebuild run, so neither libxcrun's lookup
    cache (the owner's T/xcrun_db, whatever TMPDIR says) nor xcodebuild's plug-in cache (the owner's
    C/com.apple.DeveloperTools) is written. The compile runs inside the driver's sandbox for that folder only, so
    it writes nowhere else; its module caches and TMPDIR are in it. DEVELOPER_DIR is dropped, and xcrun_db names a
    file in the folder that only an xcrun would make: a tripwire."""
    if not _guard:
        folder = tempfile.mkdtemp(prefix="larsal-guard-", dir="/tmp")
        atexit.register(shutil.rmtree, folder, True)
        binary = os.path.join(folder, "window_guard")
        env = {k: v for k, v in os.environ.items() if k != "DEVELOPER_DIR"}
        env.update(SDKROOT=os.path.realpath(SDK), TMPDIR=folder, CLANG_MODULE_CACHE_PATH=os.path.join(folder, "clang"),
                   SWIFT_MODULECACHE_PATH=os.path.join(folder, "swift"), xcrun_db=os.path.join(folder, "xcrun_db"),
                   LARSAL_TEST_INSTANCE_DIR=folder)
        subprocess.run(sandboxed([SWIFTC, "-O", "-o", binary, os.path.join(HERE, "window_guard.swift")],
                                 sandbox_profile((folder,))), check=True, capture_output=True, env=env)
        _guard.append(binary)
    return _guard[0]


class TestSites:
    """The https demo server: serves sites/<host>/ for the three test names only."""

    def __init__(self, folder, root=os.path.join(HERE, "sites")):
        key, cert = os.path.join(folder, "site-key.pem"), os.path.join(folder, "site-cert.pem")
        names = ",".join("DNS:" + h for h in HOSTS)
        # A P-256 leaf for one day; it can sign nothing (CA:FALSE) and lives only in this folder.
        subprocess.run(
            ["/usr/bin/openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1",
             "-pkeyopt", "ec_param_enc:named_curve", "-nodes", "-keyout", key, "-out", cert, "-days", "1",
             "-subj", "/CN=site-a.test", "-addext", "subjectAltName=" + names,
             "-addext", "basicConstraints=critical,CA:FALSE", "-addext", "extendedKeyUsage=serverAuth"],
            check=True, capture_output=True)
        os.chmod(key, 0o600)
        self.cert = cert
        spki = subprocess.run(["/usr/bin/openssl", "pkey", "-in", key, "-pubout", "-outform", "DER"],
                              check=True, capture_output=True).stdout
        self.spki = base64.b64encode(hashlib.sha256(spki).digest()).decode()
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert, key)

        class Handler(http.server.SimpleHTTPRequestHandler):
            protocol_version = "HTTP/1.1"  # keep-alive, as a real site

            def send_head(self):
                host = (self.headers.get("Host") or "").rsplit(":", 1)[0]
                if host not in HOSTS:
                    self.send_error(404)
                    return None
                self.directory = os.path.join(root, host)
                return super().send_head()

            def log_message(self, *args):
                pass

        class Server(http.server.ThreadingHTTPServer):
            daemon_threads = True

            def finish_request(self, request, address):
                # TLS handshake in the request's own thread, so a slow client blocks no one.
                tls = context.wrap_socket(request, server_side=True)
                try:
                    super().finish_request(tls, address)
                finally:
                    tls.close()

            def handle_error(self, request, address):
                pass  # a browser that drops a connection is not a test failure

        self.server = Server(("127.0.0.1", 0), Handler)
        self.port = self.server.server_address[1]
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def url(self, host, path="/"):
        return "https://%s:%d%s" % (host, self.port, path)

    def close(self):
        self.server.shutdown()
        self.server.server_close()


def chrome_flags(profile, spki=None):
    """Chrome's flags: Puppeteer's proven macOS defaults plus the owner-safety ones. --no-sandbox: every
    process of the run is inside the driver's sandbox, where macOS refuses the browser's own second one."""
    flags = [
        "--headless=new", "--remote-debugging-pipe", "--enable-unsafe-extension-debugging",
        "--user-data-dir=" + profile, "--use-mock-keychain", "--no-sandbox", "--no-first-run",
        "--no-default-browser-check", "--disable-background-networking", "--disable-component-update",
        "--disable-updater-scheduler", "--disable-features=MacAppCodeSignClone,OmniboxEverywhere", "--disable-sync",
        "--disable-default-apps", "--disable-breakpad", "--metrics-recording-only", "--no-proxy-server",
        "--host-resolver-rules=" + RESOLVER_RULES,
    ]
    if spki:
        flags.append("--ignore-certificate-errors-spki-list=" + spki)  # trusted by this profile only
    return flags


def _high(fd):
    """Moves a descriptor to 10 or above, so the dup2 to 3 and 4 never collides."""
    new = fcntl.fcntl(fd, fcntl.F_DUPFD_CLOEXEC, 10)
    os.close(fd)
    return new


class Session:
    """One attached target: a page or a service worker."""

    def __init__(self, chrome, session, target):
        self.chrome, self.session, self.target = chrome, session, target

    def send(self, method, params=None, timeout=30):
        return self.chrome.send(method, params, self.session, timeout)

    def navigate(self, url, timeout=30):
        since = len(self.chrome.events)
        error = self.send("Page.navigate", {"url": url}, timeout).get("errorText")
        if not error:
            try:
                return self.chrome.wait_event("Page.loadEventFired", self.session, since, timeout)
            except DriverError as e:
                error = e
        raise DriverError("%s: %s%s%s" % (url, error, self.chrome.loopback_note(),
                                          self.chrome.keep_connects("page load " + url)))

    def eval(self, expression, timeout=30, gesture=False):
        """Runs a script and returns its JSON value; a promise is awaited.
        gesture=True runs it as a user action (keep it off for no-action checks)."""
        result = self.send("Runtime.evaluate", {
            "expression": expression, "awaitPromise": True, "returnByValue": True, "userGesture": gesture,
        }, timeout)
        if "exceptionDetails" in result:
            details = result["exceptionDetails"]
            text = details.get("exception", {}).get("description", details.get("text"))
            raise DriverError("script failed: %s" % text)
        return result["result"].get("value")

    def screenshot(self, path):
        data = base64.b64decode(self.send("Page.captureScreenshot", {"format": "png"})["data"])
        with open(path, "wb") as f:
            f.write(data)
        return path

    def close(self):
        self.chrome.send("Target.closeTarget", {"targetId": self.target})


class Chrome:
    """The test browser, headless, in the driver's sandbox, with a throwaway profile under a test HOME."""

    def __init__(self, sites=None, home=None, args=()):
        self.folder = run_root("larsal-chrome-")  # the driver's run folder: also the default test HOME's root
        self.events, self.replies, self.hits = [], {}, []
        self.next_id, self.pid, self.closed = 0, None, False
        self.status, self.sent = None, set()  # the browser's wait status; the signals the driver sent it
        self.home = self.profile = self.binary = self.dumps = self.netlog = None
        self.port = self.sandbox = None  # the demo server's port and the run's sandbox profile
        self.guard = self.watcher = self._write = self._read = None
        self.front_before = self.front_after = self.before = None
        self.seen, self.kept = set(), []  # every PID pids() returned in this run; (why, path) of kept connects
        self.cv = threading.Condition()
        try:
            self._start(sites, home, list(args))
        except BaseException as e:
            note = self.keep_connects("the start: %s" % e) if self.pid else ""
            try:
                self.close()
            except DriverError as c:  # round 4: close()'s own error (a guard that stopped early) names the file too
                c.args = (str(c) + note,)
                raise
            if note and isinstance(e, DriverError):
                e.args = (str(e) + note,)
            raise

    def keep_connects(self, why):
        """C1R3-03, C2R3-05: this start's socket connect events (addresses and ports, from its NetLog) go into a
        new folder under /tmp, outside the run's folders, which close() removes; close() writes them again once
        the browser has stopped and its NetLog is whole. Returns the words that name the file in the error."""
        path = os.path.join(tempfile.mkdtemp(prefix="larsal-netlog-", dir="/tmp"), "connects.json")
        self.kept.append((why, path))
        self._write_connects(why, path)
        return " (socket connects of this start: %s)" % path

    def _write_connects(self, why, path):
        record = {"why": why, "netlog": self.netlog, "browser_running": bool(self.pid)}
        try:
            record["connects"] = connects(self.netlog)
        except (OSError, ValueError, KeyError, AttributeError, TypeError) as e:
            record["error"] = "no NetLog to read: %r" % e
        with open(path, "w") as f:
            json.dump(record, f, indent=1)

    def loopback_note(self):
        """Round 4: after a failed page load, a fresh process under this run's own sandbox profile tries TCP to the
        demo server (the driver's own listener on 127.0.0.1, so nothing leaves this Mac). Refused too means the
        run's own profile refuses the demo port, as the rule order of round 4's first profiles did for about one
        port in ten; let through means the refusal was the browser's. Returns the words for the error; none
        without the demo server."""
        if not self.port:
            return ""
        run = subprocess.Popen(sandboxed([sys.executable, "-I", "-B", "-c", LOOPBACK_PROBE, str(self.port)],
                                         self.sandbox), stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                               env={"PATH": "/usr/bin:/bin"}, text=True)
        RUN_PIDS.add(run.pid)
        try:
            answer = run.communicate(timeout=10)[0].strip() or "no answer"
        except subprocess.TimeoutExpired:
            run.kill()  # by its PID: the driver's own probe
            run.communicate()
            answer = "no answer in 10 s"
        if answer == "EPERM":
            return ("; a fresh process under this run's own sandbox profile was refused TCP to the demo server on "
                    "127.0.0.1:%d too: the run's profile refuses the demo port" % self.port)
        return "; a fresh process under this run's own sandbox profile, TCP to the demo server on 127.0.0.1:%d: %s" % (
            self.port, answer)

    def _start(self, sites, home, args):
        check_test_flags(args)  # C2R3-06: refused before anything starts
        self.binary = browser_binary()  # refused before anything starts
        BUNDLES.update({bundle_id(self.binary)} - {None})
        self.home = check_test_home(home or os.path.join(self.folder, "home"))
        # The run's own folders, the only ones it may write (C2-01): the driver's run folder (TMPDIR, the log, the
        # default HOME) and the run root that holds the test HOME, itself a folder under /tmp, never /tmp itself,
        # and one this process made or marked (C1R3-06).
        root = os.path.dirname(self.home)
        if not root.startswith("/private/tmp/"):
            raise DriverError("the test HOME must be in a folder of its run under /tmp, not in %s" % root)
        self.writable = (os.path.realpath(self.folder), check_run_root(root))
        self.dumps = crash_dumps(self.home)
        preferences = inside(self.home, PROFILE + "/Default/Preferences")  # so no link on the profile's path either
        self.profile = os.path.join(self.home, PROFILE)
        os.makedirs(os.path.dirname(preferences), exist_ok=True)
        # The DNS error page asks the system's and Google's DNS servers for google.com with its own
        # resolver, which --host-resolver-rules does not cover; this turns that probe off.
        with open(preferences, "w") as f:
            json.dump({"alternate_error_pages": {"enabled": False}}, f)
        os.makedirs(os.path.join(self.folder, "tmp"))
        self.before = owner_times()
        new_crash_reports()  # the first start of this process takes the suite's report baseline (F5)
        _BASELINE.setdefault("byhost", byhost_times())  # and the owner's ByHost entries (F1)
        flags = chrome_flags(self.profile, sites.spki if sites else None)
        # C1R3-03, C2R3-05: every start keeps a NetLog, in the driver's run folder unless the test names its own.
        given = [a.split("=", 1)[1] for a in args if a.split("=", 1)[0].lstrip("-") == "log-net-log" and "=" in a]
        self.netlog = given[-1] if given else os.path.join(self.folder, "net.json")
        if not given:
            args = args + ["--log-net-log=" + self.netlog]

        # The guard watches every process under this one, so it is armed before Chrome starts.
        self.guard = subprocess.Popen([guard_binary(), str(os.getpid())], stdin=subprocess.PIPE,
                                      stdout=subprocess.PIPE, text=True,
                                      env=dict(os.environ, LARSAL_TEST_INSTANCE_DIR=self.folder))
        ready = self.guard.stdout.readline().split()
        if ready[:1] != ["ready"]:
            raise DriverError("window guard did not start: %r" % ready)
        self.front_before = int(ready[1])
        RUN_PIDS.add(self.guard.pid)

        env = {  # CFFIXED_USER_HOME: Apple's frameworks also take the test HOME as home
            "HOME": self.home, "CFFIXED_USER_HOME": self.home, "TMPDIR": os.path.join(self.folder, "tmp"),
            "MAC_CHROMIUM_TMPDIR": os.path.join(self.folder, "tmp"),  # Chrome's temp folder; it ignores TMPDIR
            "PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "en_US.UTF-8",
            "RUSTUP_HOME": os.path.join(REAL_HOME, ".rustup"), "RUSTUP_AUTO_INSTALL": "0",
            # C2R3-02: a debug larsal-bridge under the browser finds its sockets in a run folder, never in the
            # owner's per-user temp folder (the tests' own relays name their instance folder themselves).
            "LARSAL_TEST_INSTANCE_DIR": os.path.realpath(self.folder),
        }
        to_chrome, self._write = (_high(fd) for fd in os.pipe())
        self._read, from_chrome = (_high(fd) for fd in os.pipe())
        actions = [
            (os.POSIX_SPAWN_OPEN, 0, "/dev/null", os.O_RDONLY, 0),
            (os.POSIX_SPAWN_OPEN, 1, os.path.join(self.folder, "chrome.log"),
             os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600),
            (os.POSIX_SPAWN_DUP2, 1, 2),
            (os.POSIX_SPAWN_DUP2, to_chrome, 3),  # Chrome reads DevTools commands on fd 3
            (os.POSIX_SPAWN_DUP2, from_chrome, 4),  # and writes answers and events on fd 4
        ]
        self.port = sites.port if sites else None
        self.sandbox = sandbox_profile(self.writable, (self.port,) if sites else ())
        argv = sandboxed([self.binary] + flags + args + ["about:blank"], self.sandbox)
        try:
            self.pid = os.posix_spawn(argv[0], argv, env, file_actions=actions)
        finally:
            os.close(to_chrome)
            os.close(from_chrome)
        RUN_PIDS.add(self.pid)  # from its start: the main PID is the one that could use a keychain (LD-276)
        # Started after Chrome, so a guard that stops at any time finds Chrome's PID to stop.
        self.watcher = threading.Thread(target=self._watch, daemon=True)
        self.watcher.start()
        threading.Thread(target=self._watch_owner, daemon=True).start()
        self.reader = threading.Thread(target=self._reader, daemon=True)
        self.reader.start()
        self.send("Target.getTargets")  # Chrome answers: the pipe works
        if "--use-mock-keychain" not in command_line(self.pid).split():  # the live process, LD-276
            raise DriverError("--use-mock-keychain is not on Chrome's command line: stop and report")
        if not denies_lookup(self.pid, "com.apple.cfprefsd.agent"):  # the live process, LD-285
            raise DriverError("the browser is not inside the driver's sandbox: stop and report")

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    def _watch(self):
        try:
            for line in self.guard.stdout:
                kind, pid = line.split()[:2]
                if kind == "done":
                    self.front_after = int(pid)
                else:
                    self.hits.append(line.strip())
                    self._kill()  # a window or focus: stop Chrome at once
        finally:
            if self.front_after is None:  # no "done": the guard stopped early, so Chrome runs unguarded
                self.hits.append("stopped early")
                self._kill()

    def _watch_owner(self):
        """Stops Chrome at once when an owner file changes while it runs (a service outside the sandbox may
        write for it); close() then names the file. It also notes a change of the system clock, and lists the
        run's processes at each look, so each helper joins RUN_PIDS as it appears (C2-09)."""
        while self.pid and not self.closed:
            before = self.before
            if owner_times(tuple(before)) != before:
                self._kill()
                return
            if abs(time.time() - time.monotonic() - CLOCK) > 5:
                CLOCK_STEPS.append(time.time())
            try:
                self.pids()
            except (OSError, ValueError, subprocess.SubprocessError):
                pass  # ps failed this once: the owner watch goes on; the next look, and close(), list them again
            time.sleep(0.5)

    def _kill(self):
        if self.pid:
            self.sent.add(signal.SIGKILL)
            os.kill(self.pid, signal.SIGKILL)  # our own child: until it is reaped, the PID stays ours

    def _reader(self):
        buffer = bytearray()
        while True:
            chunk = os.read(self._read, 1 << 16)
            if not chunk:
                break
            buffer += chunk
            while True:
                end = buffer.find(b"\0")
                if end < 0:
                    break
                message = json.loads(bytes(buffer[:end]))
                del buffer[:end + 1]
                with self.cv:
                    if "id" in message:
                        self.replies[message["id"]] = message
                    else:
                        self.events.append(message)
                    self.cv.notify_all()
        with self.cv:
            self.closed = True
            self.cv.notify_all()

    def send(self, method, params=None, session=None, timeout=30):
        """Sends one DevTools command and returns its result. One caller thread at a time."""
        with self.cv:
            self.next_id += 1
            number = self.next_id
        message = {"id": number, "method": method, "params": params or {}}
        if session:
            message["sessionId"] = session
        data = memoryview(json.dumps(message).encode() + b"\0")
        try:
            while data:
                data = data[os.write(self._write, data):]
        except OSError as e:
            raise DriverError("%s: Chrome's pipe is closed (%s)%s" % (method, e, self._hit_note()))
        with self.cv:
            self.cv.wait_for(lambda: number in self.replies or self.closed, timeout)
            reply = self.replies.pop(number, None)
        if reply is None:
            raise DriverError("%s: no answer from Chrome%s" % (method, self._hit_note()))
        if "error" in reply:
            raise DriverError("%s: %s" % (method, reply["error"].get("message")))
        return reply.get("result", {})

    def _hit_note(self):
        return " (window guard: %s)" % ", ".join(self.hits) if self.hits else ""

    def wait_event(self, method, session=None, since=0, timeout=30, where=lambda params: True):
        """Returns the params of the first event `method` after index `since`."""
        def find():
            for event in self.events[since:]:
                if event["method"] == method and event.get("sessionId") == session and where(event["params"]):
                    return event["params"]
        with self.cv:
            self.cv.wait_for(lambda: find() is not None or self.closed, timeout)
            params = find()
        if params is None:
            raise DriverError("no %s event%s" % (method, self._hit_note()))
        return params

    def load_extension(self, path):
        """Loads an unpacked extension and returns its id."""
        try:
            return self.send("Extensions.loadUnpacked", {"path": os.path.realpath(path)})["id"]
        except DriverError as e:
            raise DriverError("Extensions.loadUnpacked refused: stop and report; Chrome for Testing "
                              "waits for the owner's yes (rule 7): %s" % e)

    def open(self, url="about:blank", width=800, height=600):
        """Opens a new tab and returns its Session."""
        target = self.send("Target.createTarget", {"url": "about:blank"})["targetId"]
        page = self.attach(target)
        page.send("Page.enable")
        page.send("Emulation.setDeviceMetricsOverride",
                  {"width": width, "height": height, "deviceScaleFactor": 1, "mobile": False})
        if url != "about:blank":
            page.navigate(url)
        return page

    def attach(self, target):
        return Session(self, self.send("Target.attachToTarget", {"targetId": target, "flatten": True})["sessionId"],
                       target)

    def worker(self, extension_id, timeout=10, ready=30):
        """Attaches to the extension's service worker, and returns once it answers a trivial evaluate
        (each try waits at most 5 s, all of them `ready` s): a worker that is still starting may leave
        the first Runtime.evaluate without an answer (F-476), so no real one is ever the first."""
        prefix = "chrome-extension://%s/" % extension_id
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            for info in self.send("Target.getTargets")["targetInfos"]:
                if info["type"] == "service_worker" and info["url"].startswith(prefix):
                    return self.answering(self.attach(info["targetId"]), ready)
            time.sleep(0.1)
        raise DriverError("no service worker for " + extension_id)

    @staticmethod
    def answering(session, ready=30, each=5):
        """`session` once `1` evaluates to 1 in it; DriverError when no try answers within `ready` s."""
        deadline, last = time.monotonic() + ready, None
        while time.monotonic() < deadline:
            try:
                if session.eval("1", timeout=min(each, max(0.1, deadline - time.monotonic()))) == 1:
                    return session
            except DriverError as e:
                last = e
        raise DriverError("the service worker never answered a trivial evaluate: %s" % last)

    def pids(self):
        """Chrome's PID, every process under it, and every process whose command line names this
        run's profile or the test browser's crash database (the crash handler runs under launchd, not
        under Chrome). The profile, not the HOME: a test may start other programs with the same HOME
        (E7-S7c starts Larsal)."""
        rows = subprocess.run(["/bin/ps", "-axww", "-o", "pid=,ppid=,command="], check=True, capture_output=True,
                              text=True).stdout.splitlines()
        children, named = {}, []
        # Chrome gives the crash handler the /tmp form (--database=<profile>/Crashpad); it also matches /private/tmp.
        # Chromium keeps that database in the HOME, under its own name, whatever --user-data-dir says.
        profile = self.profile[len("/private"):]
        crashpad = self.home[len("/private"):] + "/Library/Application Support/Chromium/Crashpad"
        for row in rows:
            pid, ppid, command = (row.split(None, 2) + [""])[:3]
            children.setdefault(int(ppid), []).append(int(pid))
            if profile + "/" in command or crashpad + " " in command + " ":  # not "Chrome Beta": no space boundary
                named.append(int(pid))
        main = self.pid  # None once close() has stopped it (the owner watch may still be looking)
        found, todo = [], [main] if main else []
        while todo:
            pid = todo.pop()
            found.append(pid)
            todo += children.get(pid, [])
        found += [p for p in named if p not in found]
        RUN_PIDS.update(found)
        self.seen.update(found)
        return found

    def _exited(self, timeout):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                pid, status = os.waitpid(self.pid, os.WNOHANG)
            except ChildProcessError:
                return True  # reaped already
            if pid:
                self.status = status
                return True
            time.sleep(0.05)
        return False

    def close(self):
        """Stops Chrome by its PID (Browser.close, then SIGTERM), then fails on a guard hit, a
        helper left running, a process of the run as the frontmost app (another change of the frontmost
        app is the owner's own: noted in FRONT_NOTES), Chrome's updater in the test HOME, a socket of the
        run beyond loopback or a named unix socket of the run outside its folders (listed while the
        browser still runs), a new crash dump in the test HOME (listed before that HOME is removed, and
        kept: keep_dumps), a death by a signal the driver did not send (it then waits up to REPORT_WAIT s
        for macOS's crash report), or a crash report of the browser since the suite's first start or a
        changed owner file (always checked, and then the error is OwnerFilesChanged). The connect events
        kept for a failed start or page load are written again from the whole NetLog. A second call does
        nothing."""
        if self.folder is None:
            return
        helpers, outside, unix = [], [], []
        if self.pid:
            pids = self.pids()
            helpers, outside = pids[1:], outside_loopback(pids)  # LD-285: the run's own sockets, while it runs
            unix = unix_sockets_outside(pids, self.writable)  # C2R3-02
            try:
                self.send("Browser.close", timeout=5)
            except DriverError:
                pass  # the pipe may close before the answer
            if not self._exited(10):
                self.sent.add(signal.SIGTERM)
                os.kill(self.pid, signal.SIGTERM)
                if not self._exited(10):
                    self.sent.add(signal.SIGKILL)
                    os.kill(self.pid, signal.SIGKILL)
                    self._exited(10)
            self.pid = None
            self.reader.join(10)
            deadline = time.monotonic() + 10
            while helpers and time.monotonic() < deadline:
                helpers = [p for p in helpers if _alive(p)]
                time.sleep(0.05)
        for fd in (self._write, self._read):
            if fd is not None:
                os.close(fd)
        if self.guard:
            self.guard.stdin.close()
            self.guard.wait(10)
            if self.watcher:
                self.watcher.join(10)
            self.guard.stdout.close()
        problems, error = [], DriverError
        # Chrome's updater installs itself into a HOME that has none and runs launchctl in the owner's session.
        updater = [p for p in ("Library/LaunchAgents", "Library/Application Support/Google/GoogleUpdater")
                   if os.path.lexists(os.path.join(self.home, p))] if self.profile else []
        if updater:
            problems.append("Chrome's updater ran in the test HOME (stop and report): " + ", ".join(updater))
        dumps = sorted(crash_dumps(self.home) - self.dumps) if self.dumps is not None else []
        if dumps:  # F5: read before the test HOME goes, and kept outside it
            DEATHS.append(("crash dumps", dumps))
            problems.append("the browser wrote crash dumps (kept in %s): %s"
                            % (keep_dumps(self.home, dumps), ", ".join(os.path.basename(d) for d in dumps)))
        for why, path in self.kept:  # the browser has stopped: its NetLog is whole now
            self._write_connects(why, path)
        shutil.rmtree(self.folder, ignore_errors=True)
        self.folder = None
        if outside:
            problems.append("STOP (rule 7): a process of the run had a socket beyond loopback: " + ", ".join(outside))
        if unix:
            problems.append("STOP (rule 7): a process of the run had a named unix socket outside the run's folders: "
                            + ", ".join(unix))
        if helpers:
            problems.append("Chrome helpers still running after close: %s" % helpers)
        if self.hits:
            problems.append("rule 10: window guard: %s" % ", ".join(self.hits))
        if self.front_after is not None:  # None: a hit says why
            # C2R3-10: only a process of the run in front fails the run; the owner's own switch is noted.
            ours = sorted({self.front_before, self.front_after} & self.seen)
            if ours:
                problems.append("rule 10: a process of the run was the frontmost app: %s" % ours)
            elif self.front_after != self.front_before:
                FRONT_NOTES.append((self.front_before, self.front_after))
                print("note: the frontmost app changed from %s to %s, neither a process of the run (the owner's "
                      "own switch; recorded, not a failure)" % (self.front_before, self.front_after), file=sys.stderr)
        died = self.status is not None and os.WIFSIGNALED(self.status) and os.WTERMSIG(self.status)
        if died in self.sent:
            died = False  # stopped by the driver
        deadline = time.monotonic() + (REPORT_WAIT if died else 0)
        while True:  # macOS writes a crash report seconds after the crash
            reports = new_crash_reports()
            if reports or time.monotonic() >= deadline:
                break
            time.sleep(0.5)
        if died:
            DEATHS.append(("signal", died))  # check_run_end waits for a late report too
            problems.append("the browser died by signal %d, which the driver did not send" % died)
        if reports:
            problems.insert(0, "the browser left crash reports in the owner's folder (stop and report): "
                            + ", ".join(reports))
            error = OwnerFilesChanged
        if self.before is not None:
            try:
                check_owner_times(self.before)
            except OwnerFilesChanged as e:
                problems.insert(0, str(e))
                error = OwnerFilesChanged
        if problems:
            raise error("; ".join(problems))


def _alive(pid):
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False


def install_echo_host(home, extension_id):
    """Writes the echo host into the test HOME: its program, and its manifest in the
    folder Larsal writes for Chrome (INT-01.8). Returns the manifest's path."""
    home = check_test_home(home)
    folder, program = inside(home, NATIVE_HOSTS), inside(home, "echo.py")
    os.makedirs(folder, exist_ok=True)
    with open(os.path.join(HERE, "echo-host", "echo.py")) as f:
        body = f.read().split("\n", 1)[1]  # its own first line names /usr/bin/python3, an xcrun shim
    with open(program, "w") as f:
        f.write("#!%s -IB\n" % sys.executable + body)  # the suites' own interpreter, by its full path
    os.chmod(program, 0o700)
    with open(os.path.join(HERE, "echo-host", "manifest.json")) as f:
        manifest = json.load(f)
    manifest["path"] = program
    manifest["allowed_origins"] = ["chrome-extension://%s/" % extension_id]
    path = inside(home, NATIVE_HOSTS + "/" + manifest["name"] + ".json")
    with open(path, "w") as f:
        json.dump(manifest, f, indent=2)
        f.write("\n")
    return path
