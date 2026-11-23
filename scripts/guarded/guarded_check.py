#!/Applications/Xcode.app/Contents/Developer/Library/Frameworks/Python3.framework/Versions/3.9/Resources/Python.app/Contents/MacOS/Python -B -I
"""One guarded check of one commit: guarded_check.py <git-commit-or-tree-path> [--only static,rust,native,docs,fuzz]
    [--repo PATH] [--baseline FILE] [--waivers FILE] [--hold FILE] [--busy FILE [--busy-from WORDS] [--busy-to WORDS]] [--part-of ROOT]
See README.md. Exit 0 only for a full run where every step passed and every grant held; 1 FAIL, 3 NEEDS_REVIEW, 4 a part passed."""
import argparse, contextlib, fcntl, hashlib, json, os, shutil, stat, subprocess, sys, time, traceback
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import gc_lib as L
import gc_pins, gc_profiles

ORDER = ['static', 'rust', 'native', 'docs', 'fuzz']
SKIP_EMPTY = {'.git', 'target', '.serena', '.impeccable'}
HOLD_POLL, HOLD_MAX = 30, 1800
# Replace refs and grafts off: a local ref or file must not change what a commit's hash reads as, in no diff. The variable wins over the repository's own core.useReplaceRefs.
GIT_ENV = dict(L.SMALL_ENV, GIT_OPTIONAL_LOCKS='0', GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL='/dev/null', HOME='/nonexistent', DEVELOPER_DIR=L.XCODE, GIT_NO_REPLACE_OBJECTS='1', GIT_GRAFT_FILE='/dev/null')
GIT_MODES = ('100644', '100755', '120000')


def git(repo, *a, data=None):
    return subprocess.run(['/usr/bin/git', '-C', str(repo), '-c', 'core.fsmonitor=false', *a], env=GIT_ENV, input=data, capture_output=True, check=True).stdout


def resolve(arg, repo):
    # With --repo the word is a commit. Without it, only a repo's top folder counts as a tree path, so a commit word that is also a folder name stays a commit word.
    given, ref = Path(repo or '.').resolve(), arg
    if not repo and os.path.isdir(arg) and Path(git(arg, 'rev-parse', '--show-toplevel').decode().strip()) == Path(arg).resolve():
        given, ref = Path(arg).resolve(), 'HEAD'
    given = Path(git(given, 'rev-parse', '--show-toplevel').decode().strip())
    commit = git(given, 'rev-parse', '--verify', ref + '^{commit}').decode().strip()
    tree = git(given, 'rev-parse', commit + '^{tree}').decode().strip()
    return given, commit, tree


def refuse_repo(given):
    """A repository with replace refs or a shallow file is refused: what it shows is not what its commits hold."""
    refs = git(given, 'for-each-ref', '--format=%(refname)', 'refs/replace/').decode().split()
    if refs:
        raise L.Custody('repository refused: it has replace refs: %s' % refs[:5])
    shallow = git(given, 'rev-parse', '--path-format=absolute', '--git-path', 'shallow').decode().strip()
    if os.path.lexists(shallow):
        raise L.Custody('repository refused: it has a shallow file: %s' % shallow)


def hashes_at(given, commit):
    """The answer for gc_pins.evaluate: each path's tree or blob hash at the commit, None when the commit has no such path."""
    def answer(paths):
        lines = git(given, 'cat-file', '--batch-check', data=''.join('%s:%s\n' % (commit, p) for p in paths).encode()).decode().splitlines()
        assert len(lines) == len(paths)
        return {p: None if line.endswith(' missing') else line.split()[0] for p, line in zip(paths, lines)}
    return answer


def run_export(given, commit, tree, R, tool):
    """The export under its own sandbox: its only write root is R/e. The profile is outside that root. Returns the counts; the driver writes the manifest."""
    (R / 'e').mkdir()
    profile = L.seal_file(R / 'export.sb', gc_profiles.export_profile(str(R / 'e')).encode())
    q = subprocess.run([L.SANDBOX, '-f', profile, L.PY, '-B', '-I', tool / 'guarded_check.py', '--export-child', given, commit, tree, R], env=GIT_ENV, capture_output=True, stdin=subprocess.DEVNULL, timeout=L.time_left(600))
    if q.returncode:
        raise L.Custody('export refused or failed: ' + q.stderr.decode('utf-8', 'replace').strip()[-400:])
    out = json.loads(q.stdout)
    L.save(R / 'manifest.json', out['manifest'])
    return dict(out['counts'], manifest_sha256=L.sha(R / 'manifest.json'))


def export(given, commit, tree, R):
    """Exactly the tracked files of the commit, by blob. File and folder modes never gain a bit over git's and are narrowed by what the given tree has; its empty folders come along. No .serena, .impeccable or target.
    A name, a kind or a link that could write or read outside the export is refused before anything is written for it."""
    e = R / 'e'
    os.umask(0o022)
    e.mkdir(exist_ok=True)
    real = os.path.realpath(e)
    seen = {}
    listed = git(given, 'ls-tree', '-r', '-z', '--full-tree', commit).split(b'\0')
    rows = []
    q = subprocess.Popen(['/usr/bin/git', '-C', str(given), 'cat-file', '--batch'], env=GIT_ENV, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    restricted = 0
    try:
        for entry in listed:
            if not entry:
                continue
            meta, path = entry.split(b'\t', 1)
            mode, kind, blob = meta.decode().split()
            path = path.decode()
            assert kind == 'blob' and mode in GIT_MODES, 'not a regular file or link, cannot be exported: ' + path
            assert path.split('/')[0] not in SKIP_EMPTY, 'tracked file in an excluded folder: ' + path
            L.check_tree_name(path, seen)
            q.stdin.write(blob.encode() + b'\n')
            q.stdin.flush()
            head = q.stdout.readline().split()
            assert head[0].decode() == blob and head[1] == b'blob'
            size = int(head[2])
            data = q.stdout.read(size)
            q.stdout.read(1)
            f = e / path
            f.parent.mkdir(parents=True, exist_ok=True)
            if not (os.path.realpath(f.parent) + '/').startswith(real + '/'):
                raise L.Custody('refused tree name: the parent of %r leaves the export' % path)
            if mode == '120000':
                target = data.decode()
                if target.startswith('/') or os.path.normpath(os.path.join(os.path.dirname(path), target)).split('/')[0] == '..':
                    raise L.Custody('refused link: %r points outside the export' % path)
                os.symlink(data, f)
                rows.append(dict(path=path, kind='symlink', mode=stat.S_IMODE(os.lstat(f).st_mode), sha256=hashlib.sha256(data).hexdigest()))
                continue
            want = int(mode, 8) & 0o777
            try:
                disk = given / path
                if stat.S_ISREG(os.lstat(disk).st_mode):
                    narrowed = want & stat.S_IMODE(os.lstat(disk).st_mode)
                    restricted += narrowed != want
                    want = narrowed
            except FileNotFoundError:
                pass
            fd = os.open(f, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, 'wb') as out:
                out.write(data)
            os.chmod(f, want)
            rows.append(dict(path=path, kind='file', mode=want, sha256=hashlib.sha256(data).hexdigest()))
    finally:
        q.stdin.close()
        q.stdout.close()
        q.wait(timeout=30)
    # A link's text can stay inside while its chain walks out. Now every name exists, each link is resolved as the kernel would.
    for x in rows:
        if x['kind'] == 'symlink' and not (os.path.realpath(e / x['path']) + '/').startswith(real + '/'):
            raise L.Custody('refused link: %r resolves outside the export' % x['path'])
    # Empty folders of the given tree.
    empties = []
    for d, ns, fs in os.walk(given):
        rel = os.path.relpath(d, given)
        ns[:] = [n for n in ns if not (n in SKIP_EMPTY and rel == '.') and not (rel == 'fuzz' and n == 'target') and not os.path.islink(os.path.join(d, n))]
        if rel != '.' and not ns and not fs and rel.split('/')[0] not in SKIP_EMPTY:
            empties.append(rel)
            (e / rel).mkdir(parents=True, exist_ok=True)
    # Folder modes last, deepest first.
    dirs = []
    for d, ns, _ in os.walk(e, topdown=False):
        rel = os.path.relpath(d, e)
        if rel == '.':
            continue
        want = 0o755
        with contextlib.suppress(OSError):
            want &= stat.S_IMODE(os.lstat(given / rel).st_mode)
        os.chmod(d, want)
        dirs.append(dict(path=rel, kind='dir', mode=want, sha256=None))
    os.chmod(e, 0o700)
    return dict(commit=commit, tree=tree, given=str(given), rows=sorted(rows + dirs, key=lambda x: x['path'])), dict(tracked=len(rows), restricted_modes=restricted, empty_folders=len(empties), folders=len(dirs))


compare_copy = L.compare_copy


def tool_files(folder):
    return sorted(p for q in (Path(folder), Path(folder) / 'tables') if q.is_dir() for p in q.iterdir() if p.is_file() and p.name != '.DS_Store')


def tool_hashes(folder):
    return {os.path.relpath(p, folder): L.sha(p) for p in tool_files(folder)}


def copy_tool(R):
    """R/tool: read only, outside every write root, sealed."""
    t = R / 'tool'
    (t / 'tables').mkdir(mode=0o700, parents=True)
    for p in tool_files(HERE):
        L.seal_file(t / os.path.relpath(p, HERE), L.read_regular(p))
    os.chmod(t / 'tables', 0o500)
    os.chmod(t, 0o500)


def executables(toolchain):
    o = L.OWNER
    rust = o + '/.rustup/toolchains/' + toolchain + '/bin/'
    names = [L.PY, L.SANDBOX, L.NM, '/usr/bin/env', '/usr/bin/git', '/usr/bin/jq', '/usr/bin/log', '/bin/ps', '/bin/cp', '/bin/bash', L.XCODE + '/usr/bin/xcodebuild', rust + 'cargo', rust + 'rustc'] + [o + '/.cargo/bin/' + n for n in ('cargo', 'rustc', 'cargo-deny', 'cargo-audit', 'cargo-geiger', 'cargo-fuzz')]
    return {p: L.sha(os.path.realpath(p)) for p in names}


class Run:
    def __init__(self, args, R=None, commit=None):
        self.args, self.R, self.commit = args, R, commit
        self.hold_seconds = 0
        self.hold_ran_out = False
        self.marks = []  # What this run did at the busy mark beyond its own take and remove: run.json and summary.txt.

    def hold(self):
        """Wait while the hold file exists. The wait is idle time: it does not spend the total alarm, so the alarm cannot end it. Only a stop signal or HOLD_MAX does, and neither starts the step."""
        h = self.args.hold
        if not h or not os.path.exists(h):
            return
        assert not self.hold_ran_out, 'hold still there: it already ran out its %d seconds' % HOLD_MAX  # A later step does not wait it out again.
        t0 = time.monotonic()
        L.say('waiting for', h)
        while os.path.exists(h):
            assert not L.stop_signal, 'stopped by a signal during the hold'
            self.hold_ran_out = time.monotonic() - t0 >= HOLD_MAX
            assert not self.hold_ran_out, 'hold still there after %d seconds' % HOLD_MAX
            time.sleep(HOLD_POLL)
        waited = time.monotonic() - t0
        self.hold_seconds += waited
        L.extend_deadline(waited)

    def stale(self, b):
        """Why a mark found at b is a dead run's, or None: then it is someone's hold. Only one JSON line naming a pid can be stale: that pid gone, or now another process by its start time.
        The boot time counts only beside one of those (F4): a live pid with its own start time is a live run, whatever its boot field holds. Words, an empty mark, or anything unreadable is a hold."""
        try:
            st, raw = os.lstat(b), L.read_regular(b)
            mark = json.loads(raw)
            pid, start, boot = mark['pid'], mark['start'], mark['boot']
            if not (raw.endswith(b'\n') and raw.count(b'\n') == 1 and isinstance(pid, int) and pid > 0 and {'commit', 'root'} <= set(mark)):
                return None
            now = L.start_time(pid)
            why = ('its pid %d is gone' % pid if now is None else
                   'its pid %d is now another process: start time %s, the mark holds %s' % (pid, now, start) if now != start else None)
            if why and L.boot_time() != boot:
                why += '; the Mac booted since: boot time %s, the mark holds %s' % (L.boot_time(), boot)
        except (OSError, ValueError, KeyError, TypeError):
            return None
        return why and dict(event='removed as stale', mark=mark, why=why, inode=(st.st_dev, st.st_ino), raw=raw)

    def words(self, b):
        """--busy-from: the mark holds exactly that one line of words, the lead's mark handed to this run. Any other content is a hold."""
        w = self.args.busy_from
        try:
            st, raw = os.lstat(b), L.read_regular(b)
        except OSError:
            return None
        if not w or raw != w.encode() + b'\n':
            return None
        return dict(event='taken over from words', mark=w, why='the mark held exactly the --busy-from line', inode=(st.st_dev, st.st_ino), raw=raw)

    @contextlib.contextmanager
    def locked(self, b):
        """F5: the tool changes a mark only under an exclusive flock on one fixed file beside it, <mark>.lock, made once and never removed. Two runs never act on one reading."""
        fd = os.open(b + '.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            yield
        finally:
            os.close(fd)

    def put(self, b, data, found):
        """Under the lock: data goes in at b by swapping names with a new file beside it (renamex_np RENAME_SWAP), so a mark exists at every instant.
        What came out must be the file read as found, by inode and bytes: then returns (the new mark's stat, the name that now holds what came out).
        Otherwise the swap is undone and None returned; nothing else is touched, so no run's mark is ever removed by a reading that went stale (F5)."""
        tmp = '%s.%s.new' % (b, Path(self.R).name)
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            os.write(fd, data)
            made = os.fstat(fd)
        finally:
            os.close(fd)
        L.swap(tmp, b)
        st = os.lstat(tmp)
        if (st.st_dev, st.st_ino) == found['inode'] and L.read_regular(tmp) == found['raw']:
            return made, tmp
        L.swap(tmp, b)
        st = os.lstat(tmp)
        if (st.st_dev, st.st_ino) == (made.st_dev, made.st_ino):
            os.unlink(tmp)  # The new file, back beside the mark.
        self.marks.append(dict(event='changed between reading and taking: put back as it was', why=found['why'], at=time.time()))
        return None

    def take(self, b, mine):
        """One try, under the lock: made exclusively when the path is free, or swapped in for a dead run's line or the --busy-from words, which move into this root. Returns this run's mark's stat, or None for a hold."""
        with self.locked(b):
            try:
                fd = os.open(b, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            except FileExistsError:
                fd = None
            if fd is not None:
                try:
                    os.write(fd, mine)
                    return os.fstat(fd)
                finally:
                    os.close(fd)
            found = self.stale(b) or self.words(b)
            got = found and self.put(b, mine, found)
            if not got:
                return None
            dest = Path(self.R, 'busy-mark-%d-%s.txt' % (len(self.marks), 'stale' if found['event'] == 'removed as stale' else 'words'))
            os.rename(got[1], dest)
            self.marks.append(dict(event=found['event'], why=found['why'], mark=found['mark'], moved_to=str(dest), at=time.time()))
            L.say('busy mark', found['event'] + ':', found['why'])
            return got[0]

    def leave(self, b, mine, made):
        """On every way out, under the lock, and only while the mark is still this run's by inode and bytes: with --busy-to it is swapped for that one line of words, else removed. Not this run's: left alone and recorded."""
        with self.locked(b):
            try:
                st = os.lstat(b)
                ours = (st.st_dev, st.st_ino) == (made.st_dev, made.st_ino) and L.read_regular(b) == mine
            except OSError:
                ours = False
            if not ours:
                self.marks.append(dict(event='not this run\'s on the way out: left alone', at=time.time()))
                return
            if not self.args.busy_to:
                os.unlink(b)
                return
            got = self.put(b, self.args.busy_to.encode() + b'\n', dict(inode=(made.st_dev, made.st_ino), raw=mine, why='--busy-to'))
            if got:
                os.unlink(got[1])  # This run's own mark, swapped out.
                self.marks.append(dict(event='left as words', why='--busy-to', mark=self.args.busy_to, at=time.time()))

    @contextlib.contextmanager
    def busy(self):
        """The busy mark names this run in one JSON line, from before the native step's first attempt through its end compare (ruling 3). Taken by take(); a hold is waited on, polled every HOLD_POLL s for at most HOLD_MAX s; given up by leave() on every way out."""
        b = self.args.busy
        if not b:
            yield
            return
        mine = (json.dumps(dict(pid=os.getpid(), start=L.start_time(os.getpid()), commit=self.commit, root=str(self.R), boot=L.boot_time()), sort_keys=True) + '\n').encode()
        t0 = time.monotonic()
        while True:
            made = self.take(b, mine)
            if made:
                break
            assert time.monotonic() - t0 < HOLD_MAX, 'busy mark held by another run'
            time.sleep(HOLD_POLL)
        waited = time.monotonic() - t0
        self.hold_seconds += waited
        L.extend_deadline(waited)
        try:
            yield
        finally:
            self.leave(b, mine, made)


def words_line(w):
    """--busy-from and --busy-to: one line of words, never a JSON mark, so no run can read it as a dead run's."""
    if w is not None and (not w.strip() or '\n' in w or '\r' in w or w.lstrip().startswith('{')):
        raise ValueError('not one line of words: %r' % w)
    return w


def part_of(path, commit, tool, steps):
    """Ruling 6: part B names part A's root. Part A ran this commit with this very tool copy (the tool's own file hashes), steps static and rust only, and reads PASS; part B runs native, docs and fuzz. Returns what part B prints, or raises ValueError naming each mismatch."""
    if steps != ['native', 'docs', 'fuzz']:
        raise ValueError('part B runs --only native,docs,fuzz, not %s' % ','.join(steps))
    A = Path(path).resolve()
    run, s = L.load(A / 'run.json'), L.load(A / 'summary.json')
    bad = []
    if run.get('commit') != commit or s.get('commit') != commit:
        bad.append('part A ran commit %s, not %s' % (run.get('commit'), commit))
    theirs = run.get('tool_sha256') or {}
    if theirs != tool:
        bad.append('part A ran another tool copy: %s differ' % sorted(n for n in set(tool) | set(theirs) if tool.get(n) != theirs.get(n))[:10])
    if run.get('steps') != ['static', 'rust'] or s.get('requested') != ['static', 'rust']:
        bad.append('part A ran steps %s, not static,rust' % run.get('steps'))
    if s.get('overall') != 'PASS':
        bad.append('part A reads %s, not PASS' % s.get('overall'))
    if bad:
        raise ValueError('; '.join(bad))
    first = L.read_regular(A / 'summary.txt').decode('utf-8', 'replace').splitlines()[0]
    return dict(root=str(A), overall=first, total_seconds=s.get('total_seconds'), hold_wait_seconds=s.get('hold_wait_seconds'), baseline=(s.get('baseline') or {}).get('file'))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('target')
    ap.add_argument('--only', default=','.join(ORDER))
    ap.add_argument('--repo')
    ap.add_argument('--baseline')
    ap.add_argument('--waivers')
    ap.add_argument('--hold')
    ap.add_argument('--busy')
    ap.add_argument('--busy-from', type=words_line)
    ap.add_argument('--busy-to', type=words_line)
    ap.add_argument('--part-of')
    a = ap.parse_args()
    if (a.busy_from or a.busy_to) and not a.busy:
        ap.error('--busy-from and --busy-to need --busy')
    steps = a.only.split(',')
    assert steps and set(steps) <= set(ORDER), 'steps are ' + ','.join(ORDER)
    steps = [s for s in ORDER if s in steps]
    os.umask(0o077)
    import gc_summary
    started, wall = time.monotonic(), time.time()
    given, commit, tree = resolve(a.target, a.repo)
    try:  # Before any run time is spent: the summary would refuse the same files at the end.
        if a.baseline:
            gc_summary.baseline_tests(a.baseline, steps == ORDER, commit)
            if a.waivers:
                gc_summary.waiver_rows(a.waivers)
    except (OSError, ValueError) as e:
        sys.exit('refused: the baseline %s or its waivers %s: %s' % (a.baseline, a.waivers, e))
    part = None
    if a.part_of:  # Ruling 6: before the root and before any step.
        try:
            part = part_of(a.part_of, commit, tool_hashes(HERE), steps)
        except (OSError, ValueError, KeyError, IndexError, AttributeError) as e:
            sys.exit('refused: --part-of %s: %s' % (a.part_of, e))
    R = Path(subprocess.run(['/usr/bin/mktemp', '-d', '/private/tmp/larsal-gc-%s-XXXX' % commit[:7]], env=L.SMALL_ENV, capture_output=True, check=True).stdout.decode().strip())
    os.chmod(R, 0o700)
    assert len(str(R / 's')) <= 37, 'W-15: source root too long: ' + str(R / 's')
    L.start_clock()
    tool_before = tool_hashes(HERE)
    copy_tool(R)
    (R / 'results').mkdir(mode=0o700)
    assert tool_hashes(R / 'tool') == tool_before
    run = Run(a, R, commit)
    ctx = dict(R=R, tool=R / 'tool', T=L.user_temp(), hold=run.hold, busy=run.busy)
    row = dict(commit=commit, tree=tree, given=str(given), steps=steps, argv=sys.argv, baseline=a.baseline, waivers=a.waivers, T=ctx['T'], tool_sha256=tool_before, started=wall, part_of=part)
    L.say('root', R, 'commit', commit, 'steps', ','.join(steps))
    # 1. Source.
    source_row = dict(step='source', reasons=[])
    route_red, diag_before = [], None
    try:
        refuse_repo(given)
        row['grants'] = gc_pins.evaluate(R / 'tool', hashes_at(given, commit))
        ctx['withheld'] = dict(row['grants']['withheld'])
        L.say('grants: %d rows, %d withheld' % (row['grants']['rows'], len(ctx['withheld'])))
        source_row['counts'] = run_export(given, commit, tree, R, R / 'tool')
        L.say('tool against the commit:', gc_pins.tool_drift(L.load(R / 'manifest.json')['rows'], tool_before) or 'equal')
        toolchain = L.rust_toolchain(R / 'e')
        row['executables_before'] = executables(toolchain)
        route_red = gc_pins.route_failures(R / 'e', R / 'tool')
        row['sentinels_before'] = L.sentinels()
        diag_before = L.diag_names()
    except Exception as e:
        source_row['reasons'].append(str(e) if isinstance(e, L.Custody) else traceback.format_exc(limit=3))
    L.save(R / 'results/source.json', source_row)
    L.say('source', source_row.get('counts'), source_row['reasons'], route_red)
    L.save(R / 'run-start.json', row)
    ready = not source_row['reasons']
    # 2 to 6. Each step in order; a failure stops nothing unless safety requires it.
    import gc_static, gc_rust, gc_native
    runners = dict(static=gc_static.run_static, rust=gc_rust.run, native=gc_native.run, docs=gc_static.run_docs, fuzz=gc_static.run_fuzz)
    safety = None if ready else 'the source export failed'
    safety = safety or (route_red[0] if route_red else None)
    for s in steps:
        why = safety or L.stopping()
        result = dict(step=s, reasons=[], safety=None)
        if why:
            result['reasons'].append('not run: ' + why)
        else:
            t0 = time.monotonic()
            try:
                run.hold()
                L.check_sealed()
                os.umask(0o022 if s == 'native' else 0o077)
                result = runners[s](ctx)
                if L.stopping():
                    result['reasons'].append('stopped by ' + L.stopping())
                changed = {k: v for k, v in L.sentinels().items() if row['sentinels_before'][k] != v}
                if changed:
                    result['safety'] = 'owner sentinel changed: %s' % sorted(changed)
                left = L.images_under(R)
                if left:
                    result['safety'] = 'process left under the root: %s' % left
            except L.Custody as e:
                result['reasons'].append('custody: %s' % e)
                result['safety'] = 'custody: %s' % e
            except Exception:
                result['reasons'].append('step crashed: ' + traceback.format_exc(limit=4))
            result['step_seconds'] = round(time.monotonic() - t0, 1)
            os.umask(0o077)
        L.save(R / 'results' / (s + '.json'), result)
        safety = safety or result.get('safety')
        L.say(s, 'done,', len(result['reasons']), 'reasons', result.get('step_seconds'))
    # 7. Summary. Custody first: tool, executables, source copies.
    custody_changed = [n for now in (tool_hashes(HERE), tool_hashes(R / 'tool')) for n in set(now) | set(tool_before) if now.get(n) != tool_before.get(n)]
    custody_changed += [p for p, h in row.get('executables_before', {}).items() if L.sha(os.path.realpath(p)) != h]
    source_changed = []
    if ready:
        bad, new = compare_copy(R / 'e', R)
        source_changed += ['export ' + x for x in bad + new]
        if (R / 'g/source').is_dir():
            bad, new = compare_copy(R / 'g/source', R, ignore=('fuzz/target', 'fuzz/artifacts', 'target'))
            source_changed += ['static copy ' + x for x in bad + new]
        native_new = []
        if (R / 's').is_dir():
            bad, native_new = compare_copy(R / 's', R, ignore=('target',))
            source_changed += ['native copy ' + x for x in bad]
    else:
        native_new = []
    try:
        new_reports = sorted(L.diag_names() - diag_before)
        changed = sorted(k for k, v in L.sentinels().items() if row['sentinels_before'][k] != v)
    except (OSError, KeyError, TypeError) as e:  # A gate that cannot read its data fails.
        new_reports, changed = [], ['the crash folder or a sentinel could not be read: %r' % e]
    try:
        L.check_sealed()
    except L.Custody as e:
        custody_changed.append(str(e))
    row['busy_marks'] = run.marks
    row['end'] = dict(custody_changed=custody_changed, source_changed=source_changed, native_copy_new_names=native_new, sentinels_changed=changed, left_under_root=L.images_under(R), alarm=L.stopping(), diagnostic_reports_new=new_reports, total_seconds=round(time.monotonic() - started - run.hold_seconds, 1), wall_seconds=round(time.time() - wall, 1), hold_wait_seconds=round(run.hold_seconds, 1), custody=dict(tool_files=len(tool_before), executables=len(row.get('executables_before', {})), changed=len(custody_changed)))
    L.save(R / 'run.json', row)
    s = gc_summary.write(R)
    print(gc_summary.plain(s), flush=True)
    return gc_summary.exit_code(s)


if __name__ == '__main__':
    if sys.argv[1:2] == ['--export-child']:  # Runs only under the export profile: see run_export.
        manifest, counts = export(Path(sys.argv[2]), sys.argv[3], sys.argv[4], Path(sys.argv[5]))
        print(json.dumps(dict(manifest=manifest, counts=counts)))
        sys.exit(0)
    sys.exit(main())
