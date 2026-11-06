"""Grants follow reviewed content, and a lost gate fails. Two tables in tables/, both answered from the commit under test.
No flag, waiver or environment variable overrides them: a change takes a table change in a reviewed commit."""
import hashlib, re
from pathlib import Path
import gc_lib as L

BASE = 'harness-runtime-base.sb'
ROUTE_RED = "check.sh differs from the tool's route: needs a table update and review"
FUNCTION = re.compile(r'^([\w-]+)\(\) \{(?:\n.*?^\}| [^\n]*\}$)', re.M | re.S)


def table(tool, name):
    return L.load(Path(tool, 'tables', name))


# ---- Pins.
def needs_key(n):
    return 'needs:' + n['id']


def evaluate(tool, hashes_of):
    """Every row above base, against the commit. hashes_of(paths) gives each path's git tree or blob hash at the commit, None when it has none. A row with no pin is withheld too."""
    pins = table(tool, 'pins.json')
    rows = pins['rows']
    found = hashes_of(sorted({p for r in rows.values() for p in r['pins']}))
    withheld = {}
    for key, row in rows.items():
        bad = ['%s: reviewed %s, this commit %s' % (p, h, found[p]) for p, h in sorted(row['pins'].items()) if found[p] != h]
        if bad:
            withheld[key] = bad
    above = [k for k, v in table(tool, 'programs.json').items() if v['profile'] != BASE or v['classes']] + [needs_key(n) for n in table(tool, 'needs.json')]
    for key in above:
        if key not in rows:
            withheld[key] = ['no row in tables/pins.json']
    return dict(withheld=withheld, rows=len(rows), reviewed_commit=pins['reviewed_commit'])


def byte_failures(tool_pins, key, data, imports, target_tmp):
    """R2b's byte checks for one program that still holds its grant. data: its bytes; imports: its undefined symbols. Each failure is a reason to withhold."""
    out = []
    for name in tool_pins['rows'].get(key, {}).get('checks', []):
        c = tool_pins['byte_checks'][name]
        out += ['%s: imports %s' % (name, s) for s in c.get('forbid_imports', []) if s in imports]
        out += ['%s: does not import %s' % (name, s) for s in c.get('require_imports', []) if s not in imports]
        out += ['%s: bytes hold %s' % (name, s) for s in c.get('forbid_bytes', []) if s.encode() in data]
        out += ['%s: bytes do not hold %s' % (name, s) for s in c.get('require_bytes', []) if s.format(target_tmp=target_tmp).encode() not in data]
    return out


# ---- The route table.
def functions(text):
    """Each function of check.sh by its text. The table holds the text, so a table change reads as the change it approves."""
    return {m[1]: m[0] for m in FUNCTION.finditer(text)}


def check_sh_failures(text, tool):
    t = table(tool, 'routes.json')
    if hashlib.sha256(text.encode()).hexdigest() == t['check_sh_sha256']:
        return []
    now, was = functions(text), t['functions']
    changed = sorted(k for k in set(now) | set(was) if now.get(k) != was.get(k))
    return ['%s: scripts/check.sh: %s' % (ROUTE_RED, ', '.join(changed) or 'text outside the functions')]


def route_failures(source, tool):
    """check.sh by whole text and by function, the scripts its steps call, and every fuzz route by name and bytes. A new route is not a failure."""
    t = table(tool, 'routes.json')
    try:
        fails = check_sh_failures(L.read_regular(Path(source, 'scripts/check.sh')).decode('utf-8', 'replace'), tool)
    except OSError as e:
        fails = ['%s: scripts/check.sh cannot be read: %r' % (ROUTE_RED, e)]
    files = dict(t['scripts'], **{'fuzz/fuzz_targets/%s.rs' % n: h for n, h in t['fuzz_routes'].items()})
    for rel, h in sorted(files.items()):
        try:
            if L.sha(Path(source, rel)) != h:
                fails.append('%s: %s changed' % (ROUTE_RED, rel))
        except OSError:
            fails.append('%s: %s removed or not a regular file' % (ROUTE_RED, rel))
    return fails


def new_fuzz_routes(names, tool):
    return sorted(set(names) - set(table(tool, 'routes.json')['fuzz_routes']))
