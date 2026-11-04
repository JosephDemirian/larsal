"""Test driver for the installed Chrome, headless (story E7-S7b, research B11).

Python standard library only. It starts /Applications/Google Chrome.app with
--headless=new and the DevTools protocol over --remote-debugging-pipe, a
throwaway profile and a test HOME under /tmp, loads an unpacked extension with
Extensions.loadUnpacked, opens pages, runs scripts, takes screenshots and stops
Chrome by its PID. It also runs the test sites every later story uses:
site-a.test, site-b.test and sub.site-a.test on an https demo server at
127.0.0.1, with a certificate made for the run.

Owner safety, checked on every run:
- the profile is <test HOME>/Library/Application Support/Google/Chrome
  (LD-274 (7)), so the native messaging folder App writes under the test HOME
  (INT-01.8) is the one Chrome reads; the test HOME must be under /tmp;
- --use-mock-keychain: Chrome never writes to the owner's login keychain;
- --host-resolver-rules map only the three test names to 127.0.0.1 and every
  other name to ~NOTFOUND, and --no-proxy-server keeps a system proxy out, so
  no test reaches the internet; the profile turns off the DNS error page's
  probe, and --disable-updater-scheduler keeps Chrome's updater from starting
  (each has its own resolver or network access); an updater found in the test
  HOME fails the run;
- --disable-features=MacAppCodeSignClone keeps Chrome from copying its app into
  the owner's temp folder at each start; that folder is watched too;
- no path the driver writes under the test HOME goes through a link, so a
  test HOME cannot point Chrome or the echo host at the owner's Library;
- the test certificate is trusted only by this profile, through
  --ignore-certificate-errors-spki-list; nothing is added to a keychain;
- window_guard.swift (rule 10) watches the on-screen window list and the
  frontmost app, and stops at once any process of ours that shows a window or
  takes focus; when the guard itself stops early, Chrome is stopped too;
- the modification times of the owner's Chrome files are read (stat only)
  before and after; any change fails the run;
- the owner's login keychain is checked by process, not by its modification
  time, which macOS's own services change about every 10 minutes (LD-276): each
  run confirms --use-mock-keychain on the live Chrome's command line, and after
  a suite run macOS's own log shows no keychain write by a PID of the run
  (keychain_log and keychain_commits, read only).
"""

import atexit
import base64
import fcntl
import hashlib
import http.server
import json
import os
import pwd
import re
import shutil
import signal
import ssl
import subprocess
import tempfile
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
CHROME = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
PROFILE = "Library/Application Support/Google/Chrome"  # under the test HOME, LD-274 (7)
NATIVE_HOSTS = "Library/Application Support/Google/Chrome/NativeMessagingHosts"  # INT-01.8
HOSTS = ("site-a.test", "site-b.test", "sub.site-a.test")  # .test is reserved, RFC 6761
RESOLVER_RULES = ", ".join(["MAP %s 127.0.0.1" % h for h in HOSTS] + ["MAP * ~NOTFOUND"])
REAL_HOME = pwd.getpwuid(os.getuid()).pw_dir  # never $HOME: it may be a test HOME
OWNER_PATHS = tuple(
    os.path.join(REAL_HOME, "Library", p)
    for p in (
        "Preferences/com.google.Chrome.plist",
        "Application Support/Google/Chrome",
        "Application Support/Google/Chrome/Default",
        "Application Support/Google/Chrome/Local State",
        "Google",
        "Caches/Google",
    )
) + (  # Chrome clones its app here for code signing (confstr 65537: the user temp folder)
    os.path.join(os.path.dirname(os.confstr(65537).rstrip("/")), "X", "com.google.Chrome.code_sign_clone"),
)
KEYCHAIN_LOG = 'subsystem == "com.apple.securityd" AND eventMessage CONTAINS "login.keychain-db"'
RUN_PIDS = set()  # every PID of a Chrome run in this process, for keychain_commits (LD-276)
DEVELOPER_DIR = os.environ.get("DEVELOPER_DIR", "/Applications/Xcode.app/Contents/Developer")


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


_guard = []


def guard_binary():
    """Compiles window_guard.swift once per process into a folder under /tmp."""
    if not _guard:
        folder = tempfile.mkdtemp(prefix="app-guard-", dir="/tmp")
        atexit.register(shutil.rmtree, folder, True)
        binary = os.path.join(folder, "window_guard")
        env = dict(os.environ, DEVELOPER_DIR=DEVELOPER_DIR, TMPDIR=folder)
        subprocess.run(
            ["/usr/bin/xcrun", "swiftc", "-O", "-o", binary, os.path.join(HERE, "window_guard.swift")],
            check=True, capture_output=True, env=env)
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
    """Chrome's flags: Puppeteer's proven macOS defaults plus the owner-safety ones."""
    flags = [
        "--headless=new", "--remote-debugging-pipe", "--enable-unsafe-extension-debugging",
        "--user-data-dir=" + profile, "--use-mock-keychain", "--no-first-run",
        "--no-default-browser-check", "--disable-background-networking", "--disable-component-update",
        "--disable-updater-scheduler", "--disable-features=MacAppCodeSignClone", "--disable-sync",
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
        result = self.send("Page.navigate", {"url": url}, timeout)
        if result.get("errorText"):
            raise DriverError("%s: %s" % (url, result["errorText"]))
        self.chrome.wait_event("Page.loadEventFired", self.session, since, timeout)

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
    """The installed Chrome, headless, with a throwaway profile under a test HOME."""

    def __init__(self, sites=None, home=None, args=()):
        self.folder = tempfile.mkdtemp(prefix="app-chrome-", dir="/tmp")
        self.events, self.replies, self.hits = [], {}, []
        self.next_id, self.pid, self.closed = 0, None, False
        self.home = self.profile = None
        self.guard = self.watcher = self._write = self._read = None
        self.front_before = self.front_after = self.before = None
        self.cv = threading.Condition()
        try:
            self._start(sites, home, list(args))
        except BaseException:
            self.close()
            raise

    def _start(self, sites, home, args):
        self.home = check_test_home(home or os.path.join(self.folder, "home"))
        preferences = inside(self.home, PROFILE + "/Default/Preferences")  # so no link on the profile's path either
        self.profile = os.path.join(self.home, PROFILE)
        os.makedirs(os.path.dirname(preferences), exist_ok=True)
        # The DNS error page asks the system's and Google's DNS servers for google.com with its own
        # resolver, which --host-resolver-rules does not cover; this turns that probe off.
        with open(preferences, "w") as f:
            json.dump({"alternate_error_pages": {"enabled": False}}, f)
        os.makedirs(os.path.join(self.folder, "tmp"))
        self.before = owner_times()
        flags = chrome_flags(self.profile, sites.spki if sites else None)
        # Chrome takes "-name" as "--name" and the last value wins, so names are compared without dashes.
        overridden = {a.split("=", 1)[0].lstrip("-") for a in args} & {f.split("=", 1)[0].lstrip("-") for f in flags}
        if overridden:
            raise DriverError("these flags are the driver's own: " + ", ".join(sorted(overridden)))

        # The guard watches every process under this one, so it is armed before Chrome starts.
        self.guard = subprocess.Popen([guard_binary(), str(os.getpid())], stdin=subprocess.PIPE,
                                      stdout=subprocess.PIPE, text=True)
        ready = self.guard.stdout.readline().split()
        if ready[:1] != ["ready"]:
            raise DriverError("window guard did not start: %r" % ready)
        self.front_before = int(ready[1])
        RUN_PIDS.add(self.guard.pid)

        env = {  # CFFIXED_USER_HOME: Apple's frameworks also take the test HOME as home
            "HOME": self.home, "CFFIXED_USER_HOME": self.home, "TMPDIR": os.path.join(self.folder, "tmp"),
            "MAC_CHROMIUM_TMPDIR": os.path.join(self.folder, "tmp"),  # Chrome's temp folder; it ignores TMPDIR
            "PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "en_US.UTF-8", "DEVELOPER_DIR": DEVELOPER_DIR,
            "RUSTUP_HOME": os.path.join(REAL_HOME, ".rustup"), "RUSTUP_AUTO_INSTALL": "0",
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
        try:
            self.pid = os.posix_spawn(CHROME, [CHROME] + flags + args + ["about:blank"], env,
                                      file_actions=actions)
        finally:
            os.close(to_chrome)
            os.close(from_chrome)
        RUN_PIDS.add(self.pid)  # from its start: the main PID is the one that could use a keychain (LD-276)
        # Started after Chrome, so a guard that stops at any time finds Chrome's PID to stop.
        self.watcher = threading.Thread(target=self._watch, daemon=True)
        self.watcher.start()
        self.reader = threading.Thread(target=self._reader, daemon=True)
        self.reader.start()
        self.send("Target.getTargets")  # Chrome answers: the pipe works
        if "--use-mock-keychain" not in command_line(self.pid).split():  # the live process, LD-276
            raise DriverError("--use-mock-keychain is not on Chrome's command line: stop and report")

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

    def _kill(self):
        if self.pid:
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

    def worker(self, extension_id, timeout=10):
        """Attaches to the extension's service worker."""
        prefix = "chrome-extension://%s/" % extension_id
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            for info in self.send("Target.getTargets")["targetInfos"]:
                if info["type"] == "service_worker" and info["url"].startswith(prefix):
                    return self.attach(info["targetId"])
            time.sleep(0.1)
        raise DriverError("no service worker for " + extension_id)

    def pids(self):
        """Chrome's PID, every process under it, and every process whose command line names this
        run's profile (the crash handler runs under launchd, not under Chrome). The profile, not
        the HOME: a test may start other programs with the same HOME (E7-S7c starts App)."""
        rows = subprocess.run(["/bin/ps", "-axww", "-o", "pid=,ppid=,command="], check=True, capture_output=True,
                              text=True).stdout.splitlines()
        children, named = {}, []
        # Chrome gives the crash handler the /tmp form (--database=<profile>/Crashpad); it also matches /private/tmp.
        profile = self.profile[len("/private"):]
        for row in rows:
            pid, ppid, command = (row.split(None, 2) + [""])[:3]
            children.setdefault(int(ppid), []).append(int(pid))
            if profile + "/" in command:  # not "Chrome Beta"; no space boundary, a path has spaces
                named.append(int(pid))
        found, todo = [], [self.pid]
        while todo:
            pid = todo.pop()
            found.append(pid)
            todo += children.get(pid, [])
        found += [p for p in named if p not in found]
        RUN_PIDS.update(found)
        return found

    def _exited(self, timeout):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                if os.waitpid(self.pid, os.WNOHANG)[0]:
                    return True
            except ChildProcessError:
                return True  # reaped already
            time.sleep(0.05)
        return False

    def close(self):
        """Stops Chrome by its PID (Browser.close, then SIGTERM), then fails on a guard hit, a
        helper left running, a change of the frontmost app, Chrome's updater in the test HOME or a
        changed owner file (always checked, and then the error is OwnerFilesChanged). A second call
        does nothing."""
        if self.folder is None:
            return
        helpers = []
        if self.pid:
            helpers = self.pids()[1:]
            try:
                self.send("Browser.close", timeout=5)
            except DriverError:
                pass  # the pipe may close before the answer
            if not self._exited(10):
                os.kill(self.pid, signal.SIGTERM)
                if not self._exited(10):
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
        shutil.rmtree(self.folder, ignore_errors=True)
        self.folder = None
        if helpers:
            problems.append("Chrome helpers still running after close: %s" % helpers)
        if self.hits:
            problems.append("rule 10: window guard: %s" % ", ".join(self.hits))
        if self.front_after is not None and self.front_after != self.front_before:  # None: a hit says why
            problems.append("rule 10: the frontmost app changed from %s to %s (if you switched apps, run again)"
                            % (self.front_before, self.front_after))
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
    folder App writes for Chrome (INT-01.8). Returns the manifest's path."""
    home = check_test_home(home)
    folder, program = inside(home, NATIVE_HOSTS), inside(home, "echo.py")
    os.makedirs(folder, exist_ok=True)
    shutil.copyfile(os.path.join(HERE, "echo-host", "echo.py"), program)
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
