"""Grants follow reviewed content, and a lost gate fails. Two tables in tables/, both answered from the commit under test.
No flag, waiver or environment variable overrides them: a change takes a table change in a reviewed commit."""
import hashlib, os, re
from pathlib import Path
import gc_lib as L

BASE = 'harness-runtime-base.sb'
ROUTE_RED = "check.sh differs from the tool's route: needs a table update and review"
FUNCTION = re.compile(r'^([\w-]+)\(\) \{(?:\n.*?^\}| [^\n]*\}$)', re.M | re.S)
FUZZ_BIN = re.compile(r'^\[\[bin\]\]\n((?:[^\[\n].*\n?|\n)*)', re.M)
TOOL_PATH = 'scripts/guarded/'
TOOL_DRIFT = 'the running tool differs from scripts/guarded at this commit'


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


def package_folders(stream, source):
    """Cargo's own JSON for one build: each package's name and the folders, relative to the source, its artifacts were built from. The same fields `cargo metadata` gives. A package id's fragment holds name@version, or only the version when the folder has the package's name."""
    out = {}
    for x in stream:
        if x.get('reason') == 'compiler-artifact':
            url, _, frag = x['package_id'].partition('#')
            name = frag.partition('@')[0] if '@' in frag else url.rsplit('/', 1)[1]
            out.setdefault(name, set()).add(os.path.relpath(os.path.dirname(x['manifest_path']), source))
    return out


def moved_crates(row, folders):
    """A pin on crates/<name> means nothing once the build takes a package of that name from elsewhere. C1R2-01, C2R2-03: the pinned folder stays clean and no longer built."""
    names = sorted({p.split('/')[1] for p in row['pins'] if p.startswith('crates/')})
    return ['source path: package %s was built from %s, the row pins crates/%s' % (n, sorted(folders[n] - {'crates/' + n}), n) for n in names if folders.get(n, set()) - {'crates/' + n}]


def outside_folder(key, row, source, src_path, manifest_dir):
    """A grant is for the program built from its pinned folder, crates/<package>. src_path comes from Cargo's JSON, the manifest folder from the capture. A failure withholds the row as a moved pin does."""
    folder = 'crates/' + key.split(':', 1)[1].split('/')[0]
    if folder not in row['pins']:
        return ['source path: the row pins no folder %s' % folder]
    where = '%s/%s' % (source, folder)
    out = [] if manifest_dir == where else ['source path: captured manifest folder %s, the row pins %s' % (manifest_dir, folder)]
    if not os.path.normpath(src_path or '/').startswith(where + '/'):
        out.append('source path: %s is outside the pinned folder %s' % (src_path, folder))
    return out


def tool_drift(manifest_rows, tool_hashes):
    """If the commit holds scripts/guarded, the running tool's bytes must equal it, so tool and tables cannot drift from the reviewed commit. The names that differ; none when the commit holds no tool."""
    at = {x['path'][len(TOOL_PATH):]: x['sha256'] for x in manifest_rows if x['path'].startswith(TOOL_PATH) and x['kind'] != 'dir'}
    return sorted(n for n in set(at) | set(tool_hashes) if at.get(n) != tool_hashes.get(n)) if at else []


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


def fuzz_bins(text):
    """fuzz/Cargo.toml's route table: each [[bin]] by its name, as its lines without blanks or comments."""
    out = {}
    for m in FUZZ_BIN.finditer(text):
        lines = [y for y in (x.strip() for x in m[1].splitlines()) if y and not y.startswith('#')]
        name = re.fullmatch(r'name = "(.+)"', lines[0]) if lines else None
        if name:
            out[name[1]] = lines
    return out


def route_failures(source, tool):
    """check.sh by whole text and by function, the scripts its steps call, every fuzz route by name and bytes, and where fuzz/Cargo.toml points each one. A new route is not a failure."""
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
    try:
        bins = fuzz_bins(L.read_regular(Path(source, 'fuzz/Cargo.toml')).decode('utf-8', 'replace'))
    except OSError:
        bins = {}
    fails += ['%s: fuzz/Cargo.toml route %s changed or removed' % (ROUTE_RED, n) for n, lines in sorted(t['fuzz_bins'].items()) if bins.get(n) != lines]
    return fails


def new_fuzz_routes(names, tool):
    return sorted(set(names) - set(table(tool, 'routes.json')['fuzz_routes']))
