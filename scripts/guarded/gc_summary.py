"""The summary: one JSON and one plain text, built only from the files of a run root, with every count recounted from raw output.
Run alone on a private copy of a run:  gc_summary.py <run root> [--baseline FILE] [--waivers FILE]
Self-check of the parsers and the compare:  gc_summary.py --self-test"""
import json, os, re, sqlite3, stat, sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import gc_lib as L
import gc_pins

RESULT = re.compile(r'^test result: (\w+)\. (\d+) passed; (\d+) failed; (\d+) ignored; (\d+) measured; (\d+) filtered out', re.M)
TEST = re.compile(r'^test (.+?) \.\.\. (.*)$', re.M)
LINE_NO = re.compile(r' \(line (\d+)\)')
WITHHELD = 'caused by a withheld grant: '
RUST_LANES = ['workspace', 'sync', 'net', 'release', 'release-browser']
CRASH_MARKS = ('ERROR: AddressSanitizer', 'SUMMARY:', 'panicked', 'Test unit written', 'deadly signal', 'Failed to')
STEPS = ['static', 'rust', 'native', 'docs', 'fuzz']
STATES = {'ok', 'ignored', 'skipped', 'FAILED'}
# What the native build itself adds to its private source copy (target is left out of the compare). Any other new name fails.
NATIVE_OUTPUTS = ('macos/LarsalCore/Generated', 'macos/LarsalCore/.swiftpm', 'macos/Larsal.xcodeproj/project.xcworkspace')


def load(p):
    return L.load(p)


def text(p):
    """No link followed, no FIFO opened. Anything else reads as empty, and an empty log fails its reader."""
    try:
        return L.read_regular(p).decode('utf-8', 'replace')
    except OSError:
        return ''


def exit_code(s):
    """0 is a full run that passed with every grant holding. NEEDS_REVIEW outranks FAIL. A part that passed is 4, never 0."""
    if s['overall'] == 'NEEDS_REVIEW':
        return 3
    if s['overall'] != 'PASS':
        return 1
    return 4 if s['partial'] else 0


def parse_tests(raw):
    """Result lines and test names of one libtest stream. A line whose state is not plain is left out of the name states and shows as a recount mismatch."""
    totals = dict(passed=0, failed=0, ignored=0, result_lines=0, not_ok_lines=0, filtered=0)
    for m in RESULT.finditer(raw):
        totals['passed'] += int(m[2])
        totals['failed'] += int(m[3])
        totals['ignored'] += int(m[4])
        totals['result_lines'] += 1
        totals['not_ok_lines'] += m[1] != 'ok'
        totals['filtered'] += int(m[6])
    states = {}
    for m in TEST.finditer(raw):
        word = m[2].split(',')[0].split()[0] if m[2].strip() else ''
        if word in ('ok', 'ignored', 'FAILED'):
            states[m[1]] = word
    return totals, states


def rust(R, withheld=()):
    """Lanes, programs, passes and names from each program's stdout and receipt, by the plan. The failures of a row at base because its grant is withheld are labelled."""
    out, names, all_fails = {}, {}, []
    r = Path(R, 'r/state/replay')
    for lane in RUST_LANES:
        plan_file = r / (lane + '-replay-plan.json')
        if not plan_file.exists():
            all_fails.append('rust lane %s has no plan' % lane)
            continue
        plan = load(plan_file)['targets']
        row = dict(planned=len(plan), ran=0, passed=0, failed=0, ignored=0, result_lines=0)
        for x in plan:
            t, key = x['target'], x['binding']['key']
            fails = _Labelled(all_fails, WITHHELD if key in withheld else '')
            receipt = r / (lane + '-runtime') / (t + '-receipt.json')
            if not receipt.exists():
                fails.append('%s did not run (%s)' % (key, t))
                continue
            rec = load(receipt)
            row['ran'] += 1
            totals, states = parse_tests(text(r / (lane + '-runtime') / (t + '.stdout')))
            for k in ('passed', 'failed', 'ignored', 'result_lines'):
                row[k] += totals[k]
            counted = dict(ok=0, ignored=0, FAILED=0)
            for name, state in states.items():
                names['rust:%s::%s' % (key, name)] = state
                counted[state] += 1
                if state == 'FAILED':
                    fails.append('failing test: %s::%s' % (key, name))
            if rec['exit'] != 0:
                fails.append('%s exit %s%s' % (key, rec['exit'], ' helper refused: %s' % rec['helper_refusal'].get('error') if rec.get('helper_refusal') else ''))
            if not totals['result_lines'] or totals['not_ok_lines'] or totals['failed']:
                fails.append('%s result lines: %s' % (key, totals))
            if (counted['ok'], counted['ignored'], counted['FAILED']) != (totals['passed'], totals['ignored'], totals['failed']):
                fails.append('%s recount differs: names %s, result lines %s' % (key, counted, totals))
            if totals['filtered']:
                fails.append('%s filtered out %d tests' % (key, totals['filtered']))
        if row['ran'] != row['planned']:
            all_fails.append('rust lane %s ran %d of %d' % (lane, row['ran'], row['planned']))
        out[lane] = row
    totals = {k: sum(x[k] for x in out.values()) for k in ('planned', 'ran', 'passed', 'failed', 'ignored')}
    return dict(lanes=out, total=totals), names, all_fails


def swift(R, want_swift, want_app09):
    """Three readings of the Swift total, the log line, the bundle's summary and its database, each against the pinned line; APP09 from its own stream."""
    out, names, fails = {}, {}, []
    B = Path(R, 'lane-out/B1')
    log = text(B / 'xcode-test.stdout')
    m = re.search(r'^\S+ Test run with (\d+) tests? in (\d+) suites? (passed|failed) after', log, re.M)
    out['log'] = dict(tests=int(m[1]), suites=int(m[2]), state=m[3]) if m else None
    out['test_execute_succeeded'] = '** TEST EXECUTE SUCCEEDED **' in log
    try:
        s = load(B / 'results.stdout')
    except (OSError, ValueError):
        s = {}
    out['bundle'] = {k: s.get(k) for k in ('passedTests', 'failedTests', 'skippedTests', 'expectedFailures')}
    db = B / 'test.xcresult/database.sqlite3'
    out['database'] = None
    if os.path.lexists(db) and stat.S_ISREG(os.lstat(db).st_mode):
        con = sqlite3.connect('file:%s?mode=ro&immutable=1' % db, uri=True)
        rows = con.execute('select t.identifier, group_concat(distinct r.result), max(r.skipNotice_fk) from TestCases t left join TestCaseRuns r on r.testCase_fk = t.rowid group by t.rowid').fetchall()
        runs = con.execute('select count(*) from TestCaseRuns').fetchone()[0]
        con.close()
        for ident, results, skip in rows:
            state = 'skipped' if skip is not None or results == 'Skipped' else 'ok' if results == 'Success' else 'FAILED'
            names['swift:' + ident] = state
            if state == 'FAILED':
                fails.append('failing Swift test: %s (%s)' % (ident, results))
        out['database'] = dict(cases=len(rows), runs=runs, ok=sum(v == 'ok' for v in names.values()))
    if not out['log'] or out['log']['state'] != 'passed' or out['log']['tests'] != want_swift:
        fails.append('Swift total: pinned %d, log says %s' % (want_swift, out['log']))
    if out['bundle'] != dict(passedTests=want_swift, failedTests=0, skippedTests=0, expectedFailures=0):
        fails.append('Swift total: pinned %d, bundle says %s' % (want_swift, out['bundle']))
    if not out['database'] or out['database']['cases'] != want_swift or out['database']['ok'] != want_swift:
        fails.append('Swift total: pinned %d, database says %s' % (want_swift, out['database']))
    if not out['test_execute_succeeded']:
        fails.append('the test log has no TEST EXECUTE SUCCEEDED')
    app = text(B / 'app09.stdout')
    totals, states = parse_tests(app)
    out['app09'] = dict(running=[int(x) for x in re.findall(r'^running (\d+) tests?$', app, re.M)], **totals)
    for name, state in states.items():
        names['app09::' + name] = state
    if out['app09']['running'] != [want_app09] or (totals['passed'], totals['failed'], totals['ignored'], totals['filtered']) != (want_app09, 0, 0, 0):
        fails.append('APP09: pinned %d of %d, got %s' % (want_app09, want_app09, out['app09']))
    return out, names, fails


def tsv_rows(R):
    rows = {}
    for line in text(Path(R, 'g/logs/steps.tsv')).splitlines():
        a = line.split('\t')
        if len(a) >= 2:
            rows[a[0]] = dict(exit=int(a[1]), seconds=int(a[2]) if len(a) > 2 and a[2] else None)
    return rows


def static(R):
    """The steps wanted come from the route table, not from the commit: a lost step is a failure, not a smaller total."""
    fails, rows = [], tsv_rows(R)
    A = Path(R, 'g/logs/artifacts')
    t = gc_pins.table(Path(R, 'tool'), 'routes.json')
    wanted = t['g1_steps'] + t['deny_steps'] + t['audit_steps']
    for n in wanted:
        if n not in rows:
            fails.append('static step %s has no row' % n)
        elif rows[n]['exit'] != 0:
            fails.append('static step %s exit %d, log %s' % (n, rows[n]['exit'], A / (n + '.log')))
    deny, audit = text(A / 'deny.log'), text(A / 'audit.log')
    index_deny = sorted(set(sum((re.findall(r'^\s*\d+ │ (\S+) \S+ registry\+', b, re.M) for b in deny.split('warning[index-failure]')[1:]), [])))
    unproven = {k: sorted(set(re.findall(r'No such crate in crates\.io index: (\S+)', text(A / (k + '.log'))))) for k in ('audit', 'audit-fuzz', 'audit-copies')}
    advisories = re.search(r'Loaded (\d+) security advisories', audit)
    dates = []
    db = Path(R, 'g/cargo-home/advisory-db/crates')
    if db.is_dir():
        for d, _, fs in os.walk(db):
            for n in fs:
                m = re.search(r'^date = "(\d{4}-\d{2}-\d{2})"', text(os.path.join(d, n)), re.M)
                if m:
                    dates.append(m[1])
    allowed = sorted(set(re.findall(r'RUSTSEC-\d{4}-\d{4}', audit)))
    names_line = (re.findall(r'^.*files scanned.*$', text(A / 'names.log'), re.M) or [''])[-1]
    unsafe = (re.findall(r'^GC_NOTE (.*)$', text(Path(R, 'g/logs/g1.stdout')), re.M) or [''])[-1]
    limits = dict(yanked_unproven_audit=unproven, yanked_unproven_deny=index_deny, advisory_entries=int(advisories[1]) if advisories else None, advisory_newest=max(dates) if dates else None, allowed_advisory_warnings=allowed, statement='Offline copy of the index and advisory data, no fetch: the crates named here have no index entry, so their yanked status is not proven, and advisories newer than advisory_newest are not seen.')
    return dict(steps=len(wanted), passed=sum(rows.get(n, {}).get('exit') == 0 for n in wanted), names=names_line, unsafe=unsafe, deny_last=(deny.strip().splitlines() or [''])[-1], limits=limits), fails


def doc_keys(states):
    """A doc test's key holds no line number, so an edit above it does not lose it. Doc tests sharing an item are numbered in line order, so a lost one still shows."""
    out, seen = {}, {}
    def order(k):
        m = LINE_NO.search(k)
        return LINE_NO.sub('', k), int(m[1]) if m else 0
    for k in sorted(states, key=order):
        n = order(k)[0]
        seen[n] = seen.get(n, 0) + 1
        out[n if seen[n] == 1 else '%s #%d' % (n, seen[n])] = states[k]
    return out


def docs(R):
    fails, names, rows = [], {}, tsv_rows(R)
    A = Path(R, 'g/logs/artifacts')
    out = {}
    for lane in ('doc-workspace', 'doc-sync', 'doc-net'):
        raw = text(A / (lane + '.log'))
        totals, states = parse_tests(raw)
        out[lane] = totals
        counted = dict(ok=0, ignored=0, FAILED=0)
        names.update({'%s:%s' % (lane, k): v for k, v in doc_keys(states).items()})
        for name, state in states.items():
            counted[state] += 1
            if state == 'FAILED':
                fails.append('failing doc test: %s %s' % (lane, name))
        if (counted['ok'], counted['ignored'], counted['FAILED']) != (totals['passed'], totals['ignored'], totals['failed']):
            fails.append('%s recount differs: names %s, result lines %s' % (lane, counted, totals))
        if totals['filtered']:
            fails.append('%s filtered out %d tests' % (lane, totals['filtered']))
        if rows.get(lane, {}).get('exit') != 0:
            fails.append('%s exit %s, log %s' % (lane, rows.get(lane, {}).get('exit'), A / (lane + '.log')))
        if not totals['result_lines'] or totals['failed'] or totals['not_ok_lines']:
            fails.append('%s result lines: %s' % (lane, totals))
    return dict(lanes=out, total_passed=sum(x['passed'] for x in out.values()), total_failed=sum(x['failed'] for x in out.values()), result_lines=sum(x['result_lines'] for x in out.values())), names, fails


def fuzz(R):
    fails, rows = [], tsv_rows(R)
    A, src = Path(R, 'g/logs/artifacts'), Path(R, 'g/source/fuzz')
    targets = text(A / 'fuzz-list.log').split()
    declared = sorted(p.stem for p in (src / 'fuzz_targets').glob('*.rs')) if (src / 'fuzz_targets').is_dir() else []
    bins = re.findall(r'^\[\[bin\]\]', text(src / 'Cargo.toml'), re.M)
    if not targets or sorted(targets) != declared or len(bins) != len(targets):
        fails.append('fuzz routes differ: list %d, fuzz_targets %d, Cargo.toml bins %d' % (len(targets), len(declared), len(bins)))
    table = gc_pins.table(Path(R, 'tool'), 'routes.json')['fuzz_routes']
    fails += ['fuzz route removed: %s is in the route table and did not run' % n for n in sorted(set(table) - set(targets))]
    new_routes = gc_pins.new_fuzz_routes(targets, Path(R, 'tool'))
    out = []
    for t in targets:
        raw = text(A / ('fuzz-%s.log' % t))
        done = re.search(r'Done (\d+) runs in (\d+) second', raw)
        art = src / 'artifacts' / t
        crash = sorted(os.listdir(art)) if art.is_dir() else []
        marks = [m for m in CRASH_MARKS if m in raw]
        row = dict(target=t, exit=rows.get('fuzz-' + t, {}).get('exit'), runs=int(done[1]) if done else None, seconds=int(done[2]) if done else None, marks=marks, artifacts=crash)
        out.append(row)
        if row['exit'] != 0:
            fails.append('fuzz %s exit %s, log %s' % (t, row['exit'], A / ('fuzz-%s.log' % t)))
        if not done or row['seconds'] < 30:
            fails.append('fuzz %s did not run its 30 seconds: %s' % (t, done[0] if done else 'no Done line'))
        if marks or crash:
            fails.append('fuzz %s crash: marks %s, artifacts %s' % (t, marks, crash))
    return dict(new_routes=new_routes, routes=len(targets), all_exit_zero=all(x['exit'] == 0 for x in out), runs_min=min([x['runs'] or 0 for x in out], default=0), rows=out), fails


def scope_of(key):
    return {'rust': 'rust', 'swift': 'native', 'app09': 'native', 'doc-workspace': 'docs', 'doc-sync': 'docs', 'doc-net': 'docs'}.get(re.split(r'[:]', key, 1)[0])


def baseline_tests(path, full=False):
    """The baseline's tests, or ValueError naming what is wrong with its shape. Read at the start of a run, before any time is spent, and again by the summary."""
    data = load(path)
    tests = data.get('tests', data) if isinstance(data, dict) else None
    if not isinstance(tests, dict):
        raise ValueError('its tests are not a table')
    odd = [k for k, v in tests.items() if not isinstance(v, str) or v not in STATES][:3]
    if odd:
        raise ValueError('a test has no state word, so its state would not be compared: %s' % odd)
    if full:
        have = {scope_of(k) for k in tests}
        missing = [s for s in ('rust', 'native', 'docs') if s not in have]
        if missing:
            raise ValueError('it holds no tests of step %s, so a lost test would go unseen' % ', '.join(missing))
    return tests


def baseline_row(path, waivers, names, requested, full):
    """Returns the compare row and its failures. A full run without a baseline that covers each step that names tests cannot pass: nothing would catch a lost test."""
    fails, base, w = [], {}, []
    if path:
        try:
            base = baseline_tests(path, full)
            w = load(waivers)['waivers'] if waivers else []
        except (OSError, ValueError, KeyError, AttributeError) as e:
            fails.append('the baseline cannot be read: %s: %r' % (path, e))
            base = {}
    elif full:
        fails.append('a full run needs a baseline: none given, so a lost test would go unseen')
    fails += ['a waiver has no reason: %s' % x.get('test') for x in w if not x.get('why')]
    if full and path and base:
        # ponytail: half is a floor, not a count. A baseline half as long as the run passes this line, and the plain line shows the number compared.
        for s in ('rust', 'native', 'docs'):
            was, now = sum(scope_of(k) == s for k in base), sum(scope_of(k) == s for k in names)
            if was * 2 < now:
                fails.append('the baseline holds %d tests of step %s against %d in this run: too few to catch a lost test' % (was, s, now))
    row = dict(file=str(path) if path else None, waiver_file=str(waivers) if waivers else None, **compare_baseline(names, base, w, requested))
    fails += ['test lost: ' + k for k in row['lost']] + ['test newly ignored: ' + k for k in row['newly_ignored']]
    return row, fails


def compare_baseline(current, base, waivers, steps_ran):
    """Tests lost and newly ignored are failures unless the lead's waiver file lists them. Only keys of the steps that ran are compared."""
    def in_scope(key):
        return scope_of(key) in steps_ran
    base = dict({k: v for k, v in base.items() if not k.startswith('doc-')}, **doc_keys({k: v for k, v in base.items() if k.startswith('doc-')}))
    waived = {w['test'] for w in waivers}
    lost = sorted(k for k in base if in_scope(k) and k not in current)
    ignored = sorted(k for k in base if k in current and base[k] == 'ok' and current[k] in ('ignored', 'skipped'))
    new = sorted(k for k in current if k not in base)
    return dict(lost=[k for k in lost if k not in waived], newly_ignored=[k for k in ignored if k not in waived], waived=sorted(waived & (set(lost) | set(ignored))), waivers_unused=sorted(waived - set(lost) - set(ignored)), new_tests=len(new), new_test_names=new[:200], compared=sum(1 for k in base if in_scope(k)))


def summarize(R, baseline=None, waivers=None):
    R = str(R)
    run = load(Path(R, 'run.json'))
    tool = Path(R, 'tool')
    withheld = dict((run.get('grants') or {}).get('withheld') or {})
    if os.path.lexists(Path(R, 'results/rust.json')):
        withheld.update(load(Path(R, 'results/rust.json')).get('withheld_bytes') or {})
    if baseline is None:
        baseline = run.get('baseline')
    if waivers is None:
        waivers = run.get('waivers')
    requested = run['steps']
    steps, counts, names, failures, seconds = {}, {}, {}, [], {}
    results = {s: (load(Path(R, 'results', s + '.json')) if Path(R, 'results', s + '.json').exists() else None) for s in STEPS}
    source = load(Path(R, 'results/source.json')) if Path(R, 'results/source.json').exists() else None
    steps['source'] = dict(exit=0 if source and not source['reasons'] else 1)
    counts['source'] = source and source.get('counts')
    failures += ['source: ' + x for x in (source or dict(reasons=['no source row']))['reasons']]
    if not run.get('grants'):
        failures.append('this run has no grants row: the pins were never read')
    # The route table, again from the files themselves: the export, and the copy the static lanes ran in.
    route_red = set()
    for src in (Path(R, 'e'), Path(R, 'g/source')):
        if src.is_dir():
            route_red.update(gc_pins.route_failures(src, tool))
    if not (Path(R, 'e').is_dir() or Path(R, 'g/source').is_dir()):
        route_red.add('%s: no source copy to read' % gc_pins.ROUTE_RED)
    failures += sorted(route_red)
    want_swift, want_app09 = [int(x) for x in L.read_regular(tool / 'tables/native-expected.txt').split()]
    native_withheld = sorted(k for k in withheld if k.startswith('needs:'))

    def take(step, fn):
        got = fn()
        fails = list(got[-1])
        counts[step] = got[0]
        if len(got) == 3:
            names.update(got[1])
        return fails

    for s in STEPS:
        if s not in requested:
            steps[s] = dict(exit=None, note='not requested')
            continue
        row = results[s]
        fails = ['%s: %s' % (s, x) for x in (row or dict(reasons=['no result row: the step did not finish']))['reasons']]
        if row:
            seconds[s] = row.get('step_seconds')
            if row.get('safety'):
                fails.append('%s safety stop: %s' % (s, row['safety']))
        reader = dict(static=lambda: static(R), rust=lambda: rust(R, withheld), native=lambda: swift(R, want_swift, want_app09), docs=lambda: docs(R), fuzz=lambda: fuzz(R))[s]
        read = take(s, reader)
        if s == 'rust':
            fails = [lane_label(x, read) for x in fails]
        fails += ['%s: %s' % (s, x) for x in read]
        if s == 'rust' and row:
            counts['rust']['new_programs'] = row.get('new_programs', [])
            counts['rust']['import_screen'] = row.get('import_screen')
            counts['rust']['crash_reports'] = row.get('crash_reports')
            counts['rust']['seconds'] = row.get('seconds')
            counts['rust']['guard'] = {k: v.get('guard') for k, v in row.get('lanes', {}).items()}
            counts['rust']['reconcile'] = {k: dict(status=v.get('reconcile'), target_records=v.get('target_records'), source_records=v.get('source_records')) for k, v in row.get('lanes', {}).items()}
        if s == 'native' and row:
            # Information for the lead: the tool's own two binaries, and images outside the tree (other agents' builds can show here, so no gate).
            counts['native']['pins'] = {Path(k).name: v for k, v in row.get('pins', {}).items()}
            counts['native']['images_outside_tree'] = sorted({x.get('path') or '?' for k in row.get('attempts', {}) for x in (load(Path(R, 'runs', k, 'process-outside-tree.json')) if Path(R, 'runs', k, 'process-outside-tree.json').exists() else [])})
            counts['native']['attempts'] = {k: dict(exit=v['exit'], seconds=v['seconds'], window_samples=v['window_samples'], guard_requests=(v.get('guard') or {}).get('requests'), gate_failures=len(v['gate_failures'] or [])) for k, v in row.get('attempts', {}).items()}
            for k in row.get('attempts', {}):
                try:
                    fails += ['native: %s gate: %s' % (k, x) for x in load(Path(R, 'runs', k, 'gates.json'))['failures'] if ('%s: %s' % (k, x)) not in row['reasons']]
                except (OSError, ValueError):
                    fails.append('native: %s has no gates file' % k)
            if native_withheld:
                fails = [WITHHELD + x for x in fails]
        steps[s] = dict(exit=0 if not fails else 1, failures=len(fails), seconds=seconds.get(s))
        failures += fails
    # Baseline.
    partial = sorted(requested) != sorted(STEPS)
    base_row, base_fails = baseline_row(baseline, waivers, names, requested, not partial)
    failures += base_fails
    # The run as a whole.
    end = run.get('end', {})
    failures += ['owner sentinel changed: ' + k for k in end.get('sentinels_changed', ['end row missing'])]
    failures += ['process left under the root: %(pid)d %(path)s' % x for x in end.get('left_under_root', [])]
    failures += ['tool or executable changed during the run: ' + x for x in end.get('custody_changed', [])]
    failures += ['source copy changed: ' + x for x in end.get('source_changed', [])]
    failures += ['native copy new name: ' + x for x in end.get('native_copy_new_names', []) if not any(x == o or x.startswith(o + '/') for o in NATIVE_OUTPUTS)]
    if end.get('alarm'):
        failures.append('stopped by: ' + end['alarm'])
    # The commit's manifest against the tool the run took. A commit with no tool has nothing to compare.
    drift = gc_pins.tool_drift(load(Path(R, 'manifest.json'))['rows'], run.get('tool_sha256') or {}) if Path(R, 'manifest.json').exists() else []
    overall = 'NEEDS_REVIEW' if withheld or drift else 'PASS' if not failures else 'FAIL'
    out = dict(tool_drift=drift, grant_withheld=withheld, grants_read=(run.get('grants') or {}).get('rows'), overall=overall, partial=partial, requested=requested, commit=run['commit'], tree=run['tree'], root=R, steps=steps, counts=counts, baseline=base_row, failures=failures, total_seconds=end.get('total_seconds'), hold_wait_seconds=end.get('hold_wait_seconds'), custody=end.get('custody'), crash_listing=end.get('diagnostic_reports_new'), native_copy_new_names=end.get('native_copy_new_names'), where=dict(summary_json=R + '/summary.json', summary_text=R + '/summary.txt', test_names=R + '/test-names.json', static_logs=R + '/g/logs', rust_programs=R + '/r/state/replay', rust_lanes=R + '/r/state/run-lanes', native_receipts=R + '/runs', native_logs=R + '/lane-out', fuzz_logs=R + '/g/logs/artifacts'))
    return out, names


def plain(s):
    lines = ['Overall %s%s, commit %s, root %s' % (s['overall'], ' (only %s)' % ','.join(s['requested']) if s['partial'] else '', s['commit'], s['root'])]
    lines.append('grants: %s rows read, %d withheld' % (s.get('grants_read'), len(s['grant_withheld'])))
    if s['grant_withheld']:
        lines.append('grant withheld: needs review (%d). Each runs at base with no grant; a table change in a reviewed commit is the only way back:' % len(s['grant_withheld']))
        lines += ['  %s: %s' % (k, '; '.join(v)) for k, v in sorted(s['grant_withheld'].items())]
    if s.get('tool_drift'):
        lines.append('needs review: %s: %s' % (gc_pins.TOOL_DRIFT, ', '.join(s['tool_drift'])))
    for k, v in s['steps'].items():
        lines.append('%-8s exit %s%s' % (k, v.get('exit'), ', %s s' % v['seconds'] if v.get('seconds') is not None else (', ' + v['note'] if v.get('note') else '')))
    c = s['counts']
    if c.get('static'):
        x = c['static']
        lines.append('static: %d of %d steps, %s; %s; %s' % (x['passed'], x['steps'], x['names'], x['unsafe'], x['deny_last']))
        y = x['limits']
        lines.append('limit: yanked status not proven: audit %s; deny %s; advisories %s, newest %s. %s' % (y['yanked_unproven_audit'], y['yanked_unproven_deny'], y['advisory_entries'], y['advisory_newest'], y['statement']))
    if c.get('rust'):
        x = c['rust']
        lines.append('rust: %(passed)d passed, %(failed)d failed, %(ignored)d ignored, %(ran)d of %(planned)d programs' % x['total'])
        lines += ['  %s: %d passed, %d failed, %d ignored, %d of %d programs' % (k, v['passed'], v['failed'], v['ignored'], v['ran'], v['planned']) for k, v in x['lanes'].items()]
        lines.append('rust new programs (base profile only): %s' % (x.get('new_programs') or 'none'))
        lines.append('rust guard library, by lane: %s' % x.get('guard'))
    if c.get('native'):
        x = c['native']
        lines.append('swift: log %s, bundle %s, database %s' % (x['log'], x['bundle'], x['database']))
        lines.append('app09: running %s, %d passed, %d failed, %d ignored' % (x['app09']['running'], x['app09']['passed'], x['app09']['failed'], x['app09']['ignored']))
        lines.append('native binaries: %s; images outside the tree (information): %s' % (x.get('pins'), x.get('images_outside_tree')))
    if c.get('docs'):
        lines.append('docs: %d passed, %d failed, %d result lines' % (c['docs']['total_passed'], c['docs']['total_failed'], c['docs']['result_lines']))
    if c.get('fuzz'):
        lines.append('fuzz: %d routes, all exit zero %s, fewest runs %d; new routes picked up: %s' % (c['fuzz']['routes'], c['fuzz']['all_exit_zero'], c['fuzz']['runs_min'], c['fuzz'].get('new_routes') or 'none'))
    b = s['baseline']
    lines.append('baseline: %s: %d compared, %d lost, %d newly ignored, %d waived, %d new tests' % (b['file'] or 'none given', b['compared'], len(b['lost']), len(b['newly_ignored']), len(b['waived']), b['new_tests']))
    lines.append('time: %s s of the owner cap, hold wait %s s' % (s['total_seconds'], s['hold_wait_seconds']))
    on_purpose = (s['counts'].get('rust') or {}).get('crash_reports') or {}
    lines.append('crash reports new during the run: %s; on purpose: %s; own and not on purpose: %s. A report outside these belongs to another process on this Mac; a failing lane says so itself.' % (s.get('crash_listing'), ['%(child)s %(report)s' % x for x in on_purpose.get('on_purpose_children', [])], on_purpose.get('other_own_reports')))
    lines.append('native copy new names, the build\'s own: %s' % s.get('native_copy_new_names'))
    if s['failures']:
        lines.append('FAILURES (%d):' % len(s['failures']))
        lines += ['  ' + x for x in s['failures']]
    lines += ['%s: %s' % kv for kv in s['where'].items()]
    return '\n'.join(lines) + '\n'


def write(R, baseline=None, waivers=None):
    s, names = summarize(R, baseline, waivers)
    for n, data in (('summary.json', json.dumps(s, indent=1, sort_keys=True) + '\n'), ('summary.txt', plain(s)), ('test-names.json', json.dumps(dict(commit=s['commit'], tests=names), indent=0, sort_keys=True) + '\n')):
        Path(R, n).write_text(data)
    return s


def lane_label(reason, read):
    """A lane's 'program' line follows from its programs: labelled when each failing row of that lane is labelled."""
    m = re.fullmatch(r'rust: ([\w-]+): program', reason)
    if not m:
        return reason
    row = re.compile(r'(%s)?(failing test: )?%s:' % (WITHHELD, re.escape(m[1])))
    rows = [x for x in read if row.match(x)]
    return 'rust: ' + WITHHELD + reason[6:] if rows and all(x.startswith(WITHHELD) for x in rows) else reason


class _Labelled:
    """A list view: what is added lands in the one list, with this row's label."""

    def __init__(self, target, label):
        self.target, self.label = target, label

    def append(self, x):
        self.target.append(self.label + x)


def self_test():
    raw = 'running 3 tests\ntest a ... ok\ntest b ... ignored, slow\ntest c ... FAILED\ntest result: FAILED. 1 passed; 1 failed; 1 ignored; 0 measured; 0 filtered out; finished in 0.1s\n'
    totals, states = parse_tests(raw)
    assert totals == dict(passed=1, failed=1, ignored=1, result_lines=1, not_ok_lines=1, filtered=0) and states == dict(a='ok', b='ignored', c='FAILED')
    assert parse_tests('test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 7 filtered out; finished in 0s\n')[0]['filtered'] == 7
    assert LINE_NO.sub('', 'crates/a.rs - kdf::C (line 211) - compile fail') == 'crates/a.rs - kdf::C - compile fail'
    assert doc_keys({'d:s (line 9) - compile fail': 'ok', 'd:s (line 3) - compile fail': 'ignored'}) == {'d:s - compile fail': 'ignored', 'd:s - compile fail #2': 'ok'}
    assert doc_keys({'d:s - compile fail': 'ignored', 'd:s - compile fail #2': 'ok'}) == {'d:s - compile fail': 'ignored', 'd:s - compile fail #2': 'ok'}  # A baseline made by this tool stays as it is.
    assert compare_baseline({'doc-net:s - compile fail': 'ok'}, {'doc-net:s (line 3) - compile fail': 'ok', 'doc-net:s (line 9) - compile fail': 'ok'}, [], ['docs'])['lost'] == ['doc-net:s - compile fail #2']
    got = compare_baseline({'doc-net:crates/a.rs - x - compile fail': 'ok'}, {'doc-net:crates/a.rs - x (line 9) - compile fail': 'ok'}, [], ['docs'])
    assert got['lost'] == [] and got['new_tests'] == 0 and got['compared'] == 1
    assert exit_code(dict(overall='PASS', partial=False)) == 0 and exit_code(dict(overall='PASS', partial=True)) == 4 and exit_code(dict(overall='FAIL', partial=False)) == 1 and exit_code(dict(overall='NEEDS_REVIEW', partial=False)) == 3
    assert baseline_row(None, None, {}, STEPS, True)[1] and not baseline_row(None, None, {}, ['fuzz'], False)[1]
    fn = gc_pins.functions('a() {\n  x\n}\nb() { y; }\nrest\n')
    assert fn == {'a': 'a() {\n  x\n}', 'b': 'b() { y; }'}
    seen = {}
    L.check_tree_name('src/a.rs', seen)
    for bad in ('../x', '/x', 'src/../x', 'Src/b.rs', 'src/a.rs/c', '.git/config', 'a//b'):
        try:
            L.check_tree_name(bad, seen)
        except L.Custody:
            continue
        raise AssertionError('tree name taken: ' + bad)
    base = {'rust:x::a': 'ok', 'rust:x::b': 'ok', 'rust:x::c': 'ok', 'swift:s': 'ok'}
    got = compare_baseline({'rust:x::a': 'ok', 'rust:x::b': 'ignored', 'rust:x::n': 'ok'}, base, [dict(test='rust:x::c', why='moved')], ['rust'])
    assert got['lost'] == [] and got['newly_ignored'] == ['rust:x::b'] and got['waived'] == ['rust:x::c'] and got['new_tests'] == 1 and got['compared'] == 3
    got = compare_baseline({}, base, [], ['rust'])
    assert got['lost'] == ['rust:x::a', 'rust:x::b', 'rust:x::c']
    read = [WITHHELD + 'failing test: net:p/q::t', WITHHELD + 'net:p/q exit 101', 'failing test: release:p/r::t', WITHHELD + 'release:p/q exit 101']
    assert lane_label('rust: net: program', read) == 'rust: ' + WITHHELD + 'net: program'
    assert lane_label('rust: release: program', read) == 'rust: release: program'
    assert lane_label('rust: sync: program', read) == 'rust: sync: program' and lane_label('rust: net: stopped', read) == 'rust: net: stopped'
    assert gc_pins.fuzz_bins('[[bin]]\nname = "a"\n# c\n\npath = "x"\n\n[[bin]]\nname = "b"\n[dep]\nq = 1\n') == {'a': ['name = "a"', 'path = "x"'], 'b': ['name = "b"']}
    rows = [dict(path='scripts/guarded/a.py', kind='file', sha256='1'), dict(path='x', kind='file', sha256='2')]
    assert gc_pins.tool_drift(rows, {'a.py': '1'}) == [] and gc_pins.tool_drift(rows, {'a.py': '9', 'b': '1'}) == ['a.py', 'b'] and gc_pins.tool_drift(rows[1:], {'a.py': '9'}) == []
    row = dict(pins={'crates/c': 'h', 'crates/d/e.rs': 'h'})
    built = [dict(reason='compiler-artifact', package_id='path+file:///s/crates/c#0.1.0', manifest_path='/s/crates/c/Cargo.toml'), dict(reason='compiler-artifact', package_id='path+file:///s/crates/zz#d@0.1.0', manifest_path='/s/crates/zz/Cargo.toml'), dict(reason='build-finished')]
    assert gc_pins.package_folders(built, '/s') == {'c': {'crates/c'}, 'd': {'crates/zz'}}
    assert gc_pins.moved_crates(row, gc_pins.package_folders(built, '/s'))[0].startswith('source path: package d was built from')
    assert gc_pins.outside_folder('w:c/t', row, '/s', '/s/crates/c/tests/t.rs', '/s/crates/c') == []
    assert len(gc_pins.outside_folder('w:c/t', row, '/s', '/s/crates/c/../zz/t.rs', '/s/crates/zz')) == 2
    assert gc_pins.outside_folder('w:d/t', row, '/s', '/s/crates/d/t.rs', '/s/crates/d')[0].startswith('source path: the row pins no folder')
    print('self-test passed')


if __name__ == '__main__':
    a = sys.argv[1:]
    if a == ['--self-test']:
        self_test()
        sys.exit(0)
    opt = dict(zip(a[1::2], a[2::2]))
    assert set(opt) <= {'--baseline', '--waivers'}
    s = write(a[0], opt.get('--baseline'), opt.get('--waivers'))
    print(plain(s))
    sys.exit(exit_code(s))
