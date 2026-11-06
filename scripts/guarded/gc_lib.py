"""Shared helpers of the guarded check: hashes, pins, one held child, the total alarm, what the owner's Mac looks like.
Every signal goes to a process group this run started, through its Popen handle, with the leader kept unreaped so its PID stays reserved."""
import ctypes, errno, hashlib, json, os, pwd, re, select, signal, stat, subprocess, sys, time, unicodedata
from pathlib import Path

PY = '/Applications/Xcode.app/Contents/Developer/Library/Frameworks/Python3.framework/Versions/3.9/Resources/Python.app/Contents/MacOS/Python'
XCODE = '/Applications/Xcode.app/Contents/Developer'
TC = XCODE + '/Toolchains/XcodeDefault.xctoolchain/usr/bin'
NM = TC + '/llvm-nm'
SANDBOX = '/usr/bin/sandbox-exec'
SMALL_ENV = dict(PATH='/usr/bin:/bin', LC_ALL='C')
OWNER = pwd.getpwuid(os.getuid()).pw_dir
TOTAL_CAP = 3540  # The owner's cap is 3600 s; 60 s stay for the last reads and the summary.

deadline = None   # monotonic second of the total alarm
stop_signal = 0


def user_temp():
    # The T path comes from the system, never from a literal.
    out = subprocess.run(['/usr/bin/getconf', 'DARWIN_USER_TEMP_DIR'], env=SMALL_ENV, capture_output=True, check=True).stdout.decode().strip()
    return os.path.realpath(out)


def start_clock(seconds=TOTAL_CAP):
    global deadline
    deadline = time.monotonic() + seconds
    for s in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
        signal.signal(s, _on_signal)


def _on_signal(signum, frame):
    global stop_signal
    stop_signal = signum


def stopping():
    if stop_signal:
        return 'signal %d' % stop_signal
    if deadline is not None and time.monotonic() >= deadline:
        return 'total alarm'
    return None


def time_left(cap):
    return cap if deadline is None else min(cap, max(0, deadline - time.monotonic()))


def extend_deadline(seconds):
    # A hold wait is idle time: it does not spend the owner's cap.
    global deadline
    if deadline is not None:
        deadline += seconds


# ---- Files. Every read of a path a lane could write goes through here: no link is followed and no FIFO can block past the alarm.
class Custody(Exception):
    """A sealed file changed, or the commit under test tried something the export refuses. A safety reason: the steps left do not start."""


def _open_regular(p):
    fd = os.open(p, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    if not stat.S_ISREG(os.fstat(fd).st_mode):
        os.close(fd)
        raise OSError(errno.EINVAL, 'not a regular file', str(p))
    return fd


def sha(p):
    h = hashlib.sha256()
    fd = _open_regular(p)
    try:
        for b in iter(lambda: os.read(fd, 4194304), b''):
            h.update(b)
    finally:
        os.close(fd)
    return h.hexdigest()


def read_regular(p, start=0):
    fd = _open_regular(p)
    try:
        os.lseek(fd, start, os.SEEK_SET)
        return b''.join(iter(lambda: os.read(fd, 4194304), b''))
    finally:
        os.close(fd)


def load(p):
    return json.loads(read_regular(p))


# Sealed files: generated profiles, the tool copy, the guard library. Outside every write root, read only, their hashes held only in this process, compared before every use.
SEALED = {}


def seal_file(p, data, mode=0o400):
    fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as f:
        f.write(data)
    os.chmod(p, mode)
    SEALED[str(p)] = hashlib.sha256(data).hexdigest()
    return p


def seal_existing(p):
    SEALED[str(p)] = sha(p)
    return p


def sealed(p):
    try:
        same = sha(p) == SEALED.get(str(p))
    except OSError as e:
        raise Custody('sealed file unreadable: %s: %r' % (p, e))
    if not same:
        raise Custody('sealed file changed: %s' % p)
    return p


def check_sealed():
    for p in list(SEALED):
        sealed(p)


# ---- A tree name is refused before anything is written for it.
def check_tree_name(path, seen):
    """No empty, dot or dot-dot part, no absolute path, no .git part, no name that folds onto another, no name below a file or link. seen: folded prefix -> (prefix, kind)."""
    parts = path.split('/')
    if path.startswith('/') or any(x in ('', '.', '..') or x.casefold() == '.git' for x in parts):
        raise Custody('refused tree name: %r' % path)
    for i in range(1, len(parts) + 1):
        prefix = '/'.join(parts[:i])
        row = (prefix, 'folder' if i < len(parts) else 'leaf')
        old = seen.setdefault(unicodedata.normalize('NFD', prefix).casefold(), row)
        if old != row or (row[1] == 'leaf' and old is not row):
            raise Custody('refused tree name: %r collides with %r on a folding filesystem, or sits below a file or link' % (path, old[0]))


def save(p, x):
    with Path(p).open('x') as f:
        json.dump(x, f, indent=1, sort_keys=True)
        f.write('\n')


def mkdirs(*paths):
    for p in paths:
        Path(p).mkdir(mode=0o700, parents=True, exist_ok=True)


def pin(p):
    """What the plans compared: identity and bytes. No FIFO or socket is ever opened: regular files only, after lstat, with O_NOFOLLOW."""
    st = os.lstat(p)
    x = dict(path=str(p), device=st.st_dev, inode=st.st_ino, mode=stat.S_IMODE(st.st_mode), kind=stat.S_IFMT(st.st_mode), size=st.st_size, mtime_ns=st.st_mtime_ns, ctime_ns=st.st_ctime_ns, uid=st.st_uid, gid=st.st_gid, nlink=st.st_nlink, flags=st.st_flags)
    if stat.S_ISREG(st.st_mode):
        x['sha256'] = sha(p)
    elif stat.S_ISLNK(st.st_mode):
        x['link'] = os.readlink(p)
    elif not stat.S_ISDIR(st.st_mode):
        x['unexpected_vnode'] = True
    return x


def tree(root, skip=()):
    """Every path under root, pinned. A folder in skip is recorded itself, its contents are not."""
    root = str(root)
    live = {root: pin(root)}
    for d, ns, fs in os.walk(root, followlinks=False):
        if d in skip:
            ns[:] = []
            continue
        for n in ns + fs:
            q = os.path.join(d, n)
            live[q] = pin(q)
    return live


def identity(p):
    s = Path(p).stat()
    return dict(device=s.st_dev, inode=s.st_ino, size=s.st_size, mode=stat.S_IMODE(s.st_mode), mtime_ns=s.st_mtime_ns, uid=s.st_uid)


# ---- One held child.
def ps_rows(flag, value):
    q = subprocess.run(['/bin/ps', flag, value, '-o', 'pid=,ppid=,pgid=,stat=,comm='], env=SMALL_ENV, stdin=subprocess.DEVNULL, capture_output=True, timeout=10)
    # ps exits 1 with empty stderr when nothing matches. Anything else means the read failed: a row that can only fail the run, so a survivor is never missed by timing.
    if q.returncode not in (0, 1) or q.stderr:
        return [dict(pid=-1, parent=-1, pgid=int(value) if flag == '-g' else -1, state='?', image='ps failed: %r' % q.stderr[:100])]
    rows = []
    for line in q.stdout.decode('utf-8', 'replace').splitlines():
        a = line.split(None, 4)
        if len(a) == 5:
            rows.append(dict(pid=int(a[0]), parent=int(a[1]), pgid=int(a[2]), state=a[3], image=a[4]))
    return rows


def group_rows(leader):
    """Live members of the group by PID, parent and image, without the leader. Names a survivor before any signal goes out."""
    return [x for x in ps_rows('-g', str(leader)) if x['pgid'] == leader and x['pid'] != leader and not x['state'].startswith('Z')]


def group_rows_any(pids):
    return ps_rows('-p', ','.join(str(p) for p in pids)) if pids else []


def signal_group(proc, sig):
    # Only while the leader is unreaped: its PID, so its group ID, cannot have been reused.
    assert proc.returncode is None
    try:
        os.killpg(proc.pid, sig)
        return True
    except (ProcessLookupError, PermissionError):
        return False


def group_absent(pid):
    try:
        os.killpg(pid, 0)
        return False
    except ProcessLookupError:
        return True
    except PermissionError:
        return False


def wait_exit(proc, until, check=None, obey_alarm=True):
    """kqueue NOTE_EXIT, leader left unreaped. None when it exited, else why the wait ended."""
    q = select.kqueue()
    try:
        try:
            q.control([select.kevent(proc.pid, filter=select.KQ_FILTER_PROC, flags=select.KQ_EV_ADD | select.KQ_EV_ONESHOT, fflags=select.KQ_NOTE_EXIT)], 0, 0)
        except ProcessLookupError:
            return None  # A fast child exited before the registration.
        while True:
            why = (stopping() if obey_alarm else None) or ('cap' if time.monotonic() >= until else None) or (check() if check else None)
            if why:
                return why
            if q.control(None, 1, min(.25, max(.001, until - time.monotonic()))):
                return None
    finally:
        q.close()


def close_group(proc, until=30):
    """After the leader's exit. Same-group members are named by PID and image, get the SIGKILL while the PID is reserved, are read again, and only then is the leader reaped."""
    seen = group_rows(proc.pid)
    signaled = signal_group(proc, signal.SIGKILL)
    code = proc.wait(timeout=until)
    end = time.monotonic() + 5
    left = group_rows(proc.pid)
    while left and time.monotonic() < end:
        time.sleep(.05)
        left = group_rows(proc.pid)
    return dict(exit=code, survivors=seen, survivor_signaled=signaled, left_after_kill=left, group_absent=group_absent(proc.pid))


def stop_group(proc, grace=20):
    signal_group(proc, signal.SIGTERM)
    wait_exit(proc, time.monotonic() + grace, obey_alarm=False)


def held(argv, cwd, env, out, err, cap, check=None, preexec=None, grace=20, on_start=None):
    """One child in its own group, capped by cap and the total alarm. Every way out returns a row."""
    start = time.monotonic()
    row = dict(argv=[str(a) for a in argv], cwd=str(cwd), cap=round(cap, 1), stopped=None)
    with open(out, 'xb') as o, open(err, 'xb') as e:
        p = subprocess.Popen([str(a) for a in argv], cwd=cwd, env=env, stdin=subprocess.DEVNULL, stdout=o, stderr=e, start_new_session=True, preexec_fn=preexec)
        row['pid'] = p.pid
        if on_start:
            on_start(p.pid)
        row['stopped'] = wait_exit(p, start + cap, check)
        if row['stopped']:
            stop_group(p, grace)
        row.update(close_group(p))
    row['seconds'] = round(time.monotonic() - start, 3)
    return row


def row_clean(row):
    """Exit 0, not stopped, nothing left in its group."""
    return row.get('exit') == 0 and not row.get('stopped') and not row.get('survivors') and row.get('group_absent')


# ---- The owner's Mac: read only.
SENTINELS = ['Library/Preferences/com.apple.dt.Xcode.plist', 'Library/Preferences/com.apple.dt.xcodebuild.plist', 'Library/Developer/Xcode/DerivedData', 'Library/Developer/Xcode/UserData', 'Library/Caches/org.swift.swiftpm', 'Library/org.swift.swiftpm', '.cargo/config.toml', '.swiftpm']


def sentinels(owner=OWNER):
    out = {}
    for p in SENTINELS:
        try:
            s = os.lstat(owner + '/' + p)
            out[p] = dict(mtime_ns=s.st_mtime_ns, ctime_ns=s.st_ctime_ns, inode=s.st_ino)
        except FileNotFoundError as e:
            out[p] = e.errno
    return out


LIB = ctypes.CDLL('/usr/lib/libproc.dylib')
LIB.proc_pidpath.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_uint32]
LIB.proc_listallpids.argtypes = [ctypes.c_void_p, ctypes.c_int]


def image(pid):
    buf = ctypes.create_string_buffer(4096)
    return buf.value.decode('utf-8', 'replace') if LIB.proc_pidpath(pid, buf, len(buf)) > 0 else None


def images_under(root):
    """Any live process whose image sits under the run root."""
    n = LIB.proc_listallpids(None, 0)
    ids = (ctypes.c_int * (n + 256))()
    got = LIB.proc_listallpids(ids, ctypes.sizeof(ids))
    root = str(root)
    rows = []
    for pid in list(ids)[:max(got, 0)]:
        path = image(pid) if pid > 0 else None
        if path and (path.startswith(root + '/') or path.startswith(root[len('/private'):] + '/')):
            rows.append(dict(pid=pid, path=path))
    return rows


def diag_names(owner=OWNER):
    try:
        return set(os.listdir(owner + '/Library/Logs/DiagnosticReports'))
    except FileNotFoundError:
        return set()


REPORT_NAME = re.compile(r'(.+?)-\d{4}-\d{2}-\d{2}-\d{6}')
ON_PURPOSE = re.compile(r'\d+(guard_child|prompt_child)')  # The two larsal_platform tests that raise SIGQUIT in a forked child on purpose.


def on_purpose_child(owner, name):
    """Which of the two known children wrote this report, or None. Reads only a report that bears this run's own test program name."""
    p = owner + '/Library/Logs/DiagnosticReports/' + name
    try:
        _, _, rest = read_regular(p).decode('utf-8', 'replace').partition('\n')
        body = json.loads(rest)
    except (OSError, ValueError):
        return None
    if body.get('exception', {}).get('signal') != 'SIGQUIT':
        return None
    frames = [f.get('symbol', '') for t in body.get('threads', []) if t.get('triggered') for f in t.get('frames', [])]
    hit = {m.group(1) for f in frames for m in [ON_PURPOSE.search(f)] if m}
    return sorted(hit)[0] if len(hit) == 1 else None


def rust_toolchain(source):
    """The pinned Rust channel, read from the source given, as the triple the routes name."""
    m = re.search(r'^channel = "([0-9.]+)"$', read_regular(Path(source, 'rust-toolchain.toml')).decode(), re.M)
    assert m, 'rust-toolchain.toml names no numbered channel'
    name = m.group(1) + '-aarch64-apple-darwin'
    assert os.path.isdir(OWNER + '/.rustup/toolchains/' + name), 'toolchain not installed: ' + name
    return name


def swiftlint_path(source, home):
    """check.sh's answer for the pinned binary, read from its install script: $HOME/.local/share/swiftlint/<version>/swiftlint."""
    m = re.search(r'^VERSION=([0-9.]+)$', read_regular(Path(source, 'scripts/install-swiftlint.sh')).decode(), re.M)
    assert m, 'no SwiftLint version in scripts/install-swiftlint.sh'
    return '%s/.local/share/swiftlint/%s/swiftlint' % (home, m.group(1))


def absent_configs(source, cargo_home):
    """Cargo config files Cargo would read and the route does not expect. None may exist: the source's own .cargo/config.toml is the only one."""
    out = [str(Path(source) / '.cargo/config')]
    for p in Path(source).parents:
        out += [str(p / '.cargo/config'), str(p / '.cargo/config.toml')]
    return out + [str(Path(cargo_home) / 'config'), str(Path(cargo_home) / 'config.toml')]


# ---- The guard library: one build per run, from the tool copy, read by the Rust rows that hold a board or window line and by xctest.
def guard_dylib(R, tool):
    R = Path(R)
    out = R / 'bin/guard-board.dylib'
    if str(out) in SEALED:
        return sealed(out)
    for n in ('bin', 'home', 'tmp', 'modules', 'modules/clang'):
        (R / n).mkdir(mode=0o700, exist_ok=True)
    sdk = XCODE + '/Platforms/MacOSX.platform/Developer/SDKs/MacOSX.sdk'
    env = dict(PATH='/usr/bin:/bin', HOME=str(R / 'home'), TMPDIR=str(R / 'tmp') + '/', DEVELOPER_DIR=XCODE, CLANG_MODULE_CACHE_PATH=str(R / 'modules/clang'))
    subprocess.run([TC + '/clang', '-isysroot', sdk, '-mmacosx-version-min=14.0', '-O1', '-dynamiclib', '-o', 'bin/guard-board.dylib', 'tool/guard-board.c', '-framework', 'AppKit', '-framework', 'CoreFoundation', '-lobjc'], cwd=R, env=env, check=True)
    os.chmod(out, 0o500)
    want = load(Path(tool, 'tables/routes.json'))['binaries']['guard-board.dylib']
    if sha(out) != want:
        raise Custody('the guard library hash %s differs from the table %s' % (sha(out), want))
    return seal_existing(out)


# ---- The guard log: the same gate for xctest and for the Rust rows.
TELEMETRY = {'_NSPasteboardSetPasteVerificationTelemetry', '___NSPasteboardInstallPrevalidationCallbacks_block_invoke'}  # AppKit's own set-up, seen in the discovery run.
REQUEST = re.compile(r'^(\d+) pid (\d+) (\+generalPasteboard|CFPasteboardCreate general|\+pasteboardWithName: general)$')
LOADED = re.compile(r'^(\d+) pid (\d+) loaded, (.*)$')
FRAME = re.compile(r'^\d+\s+(\S+)\s+0x[0-9a-f]+\s+(.*?) \+ \d+$')
OURS = re.compile(r'^(?:Larsal|LarsalTests|LarsalCore|larsal.*)$')


def gate_guard(text, must_load):
    """Each general request must come straight from an AppKit set-up frame. Our frames lower on the stack are the route into AppKit and are counted, not failed: the first frame after the guard decides who asked."""
    report = dict(requests=0, telemetry_first=0, our_frame_lower_on_stack=0, loaded_pids=[], not_found_lines=0, bad=[])
    fails = []
    stacks, cur = [], None
    for line in text.splitlines():
        if LOADED.match(line):
            m = LOADED.match(line)
            if m[3] == 'both methods replaced':
                report['loaded_pids'].append(int(m[2]))
            else:
                report['not_found_lines'] += 1
            cur = None
        elif REQUEST.match(line):
            cur = [line]
            stacks.append(cur)
        elif cur is not None and FRAME.match(line):
            cur.append(line)
        elif cur is not None and line.strip():
            fails.append('guard log line not understood: ' + line[:120])
    for s in stacks:
        report['requests'] += 1
        frames = [FRAME.match(x).groups() for x in s[1:]]
        after = [f for f in frames if f[0] != 'guard-board.dylib']
        first = after[0] if after else ('', '')
        if first[0] == 'AppKit' and first[1] in TELEMETRY:
            report['telemetry_first'] += 1
        else:
            report['bad'].append(s[0] + ' first caller ' + ' '.join(first))
            fails.append('general board request not from an AppKit set-up frame: %s, first caller %s %s' % (s[0], first[0], first[1]))
        if any(OURS.match(f[0]) for f in after[1:]):
            report['our_frame_lower_on_stack'] += 1
    if report['not_found_lines']:
        fails.append('the guard failed to load: %d "methods NOT found" lines' % report['not_found_lines'])
    missing = sorted(set(must_load) - set(report['loaded_pids']))
    if missing:
        fails.append('the guard failed to load: no load line for pid %s' % missing)
    return fails, report


def say(*a):
    print(time.strftime('%H:%M:%S'), *a, flush=True)
    sys.stdout.flush()
