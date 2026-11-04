#!/usr/bin/env bash
# Bill of materials and third-party notices (E14-S4, E14-S2, LD-222).
# Lists every crate that ships in the `larsal` tool and in Larsal.app (linked
# code, plus proc macros and the Swift generator, whose output ships; not
# what only runs at build time) from Cargo.lock and the crates' own files.
# Written to the release folder (default ${CARGO_TARGET_DIR:-target}/repro,
# as scripts/repro-build.sh), never kept in the tree: the notices carry each
# crate's copyright lines word for word, outside product names included.
#
#   sbom.cdx.json            CycloneDX 1.6: versions, licenses, Cargo.lock
#                            checksums, patched copies marked
#   THIRD-PARTY-NOTICES.md   every license text, each once
#   rust-std-COPYRIGHT.html  the Rust standard library's notices
#
# scripts/licenses/ holds the standard texts for crates that publish none.
# Larsal's own license is in LICENSE (E14-S2); the built-in word
# list's attribution is larsal-core's wordlist.rs ATTRIBUTION, read from there.
# The Public Suffix List larsal-browser compiles in is listed with its MPL-2.0
# text (vendor/public-suffix-list/, LD-322 (7)).
# scripts/build-core.sh puts the three files in Larsal.app (E14-S2).
#
#   scripts/make-sbom.sh [folder]
set -euo pipefail
cd "$(dirname "$0")/.."
command -v cargo >/dev/null || . "$HOME/.cargo/env"
# The same fixed time as scripts/repro-build.sh, so the files are reproducible.
export SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH:-1793232000}
out=${1:-${CARGO_TARGET_DIR:-target}/repro}
mkdir -p "$out"
tmp=$(mktemp -d "${TMPDIR:-/tmp}/larsal-sbom.XXXXXX") || exit 1
trap 'rm -rf "$tmp"' EXIT
tree() { cargo tree --offline --locked -e normal --target aarch64-apple-darwin --prefix depth -f '{p}' "$@"; }
tree -p larsal-cli >"$tmp/larsal.txt"
tree -p larsal-ffi --features net >"$tmp/Larsal.app.txt"
cargo metadata --offline --locked --all-features --format-version 1 --filter-platform aarch64-apple-darwin >"$tmp/meta.json"
python3 -I - "$tmp" "$out" "$(rustc --print sysroot)" "$(rustc --version)" <<'PY'
import datetime, json, os, re, shutil, sys

tmp, out, sysroot, rustc = sys.argv[1:]
root = os.getcwd()
meta = json.load(open(f"{tmp}/meta.json"))
pkgs = {(p["name"], p["version"]): p for p in meta["packages"]}
members = set(meta["workspace_members"])
license_name = open("LICENSE").readline().strip()
if not license_name:
    raise SystemExit("make-sbom: LICENSE has no license name")
own_license = [{"license": {"name": license_name}}]
version = {n: v for n, v in pkgs}  # for Larsal's own crates, one version each
lock = {}
for b in open("Cargo.lock").read().split("[[package]]"):
    m, c = re.search(r'name = "([^"]+)"\nversion = "([^"]+)"', b), re.search(r'checksum = "(\w+)"', b)
    if m and c:
        lock[m.groups()] = c.group(1)

# cargo tree --prefix depth: "<depth><name> v<version>[ (path|proc-macro)][ (*)]".
ships, edges = {}, set()
for prod in ("larsal", "Larsal.app"):
    kids, macros, stack, todo = {}, set(), [], []
    for line in open(f"{tmp}/{prod}.txt"):
        d, name, ver, rest = re.match(r"(\d+)(\S+) v(\S+)(.*)", line).groups()
        node = (name, ver)
        del stack[int(d):]
        kids.setdefault(stack[-1], set()).add(node) if stack else todo.append(node)
        stack.append(node)
        if "(proc-macro)" in rest:
            macros.add(node)
    seen = set()
    while todo:  # a proc macro ships its output, not its own dependencies
        n = todo.pop()
        if n not in seen:
            seen.add(n)
            if n not in macros:
                todo += kids.get(n, [])
                edges |= {(n, k) for k in kids.get(n, [])}
    if prod == "Larsal.app":  # its Swift glue comes from uniffi_bindgen's templates
        seen |= {k for k in pkgs if k[0] == "uniffi_bindgen"}
    for n in seen:
        ships.setdefault(n, set()).add(prod)

# Patched copies: [patch.crates-io] in Cargo.toml, with the comment above each.
patch, notes = {}, []
for line in open("Cargo.toml").read().split("\n"):
    m = re.match(r'([\w-]+) = \{ path = "(vendor/[^"]+)" \}', line)
    if line.startswith("#"):
        notes.append(line.lstrip("# "))
    elif m:
        patch[m.group(1)], notes = (m.group(2), " ".join(notes)), []
    elif line != "[patch.crates-io]":
        notes = []

spdx = lambda e: re.sub(r"\s*/\s*", " OR ", e)  # the old "MIT/Apache-2.0" form
norm = lambda t: "\n".join(l.rstrip() for l in t.replace("\r\n", "\n").strip().split("\n"))
pat = re.compile(r"(licen[cs]e|copying|notice|unlicense|copyright|authors)", re.I)
std_texts = {"MIT": "scripts/licenses/MIT.txt", "MPL-2.0": "scripts/licenses/MPL-2.0.txt"}

comps, texts, rows, missing = [], {}, [], []
for key in sorted(ships, key=lambda k: (k[0].lower(), k)):
    (name, ver), p, used = key, pkgs[key], ", ".join(sorted(ships[key]))
    d = os.path.dirname(p["manifest_path"])
    # Patched copies come from [patch.crates-io]; a plain copy made by source
    # replacement (cargo vendor, LD-221) keeps its crates.io source and checksum.
    vendored = name in patch and os.path.relpath(d, root) == patch[name][0]
    c = {"type": "library", "bom-ref": f"{name}@{ver}", "name": name, "version": ver, "scope": "required",
         "properties": [{"name": "larsal:ships-in", "value": used}]}
    comps.append(c)
    if p["id"] in members:
        if p["license"] is not None or not p["license_file"] or os.path.realpath(os.path.join(d, p["license_file"])) != os.path.realpath("LICENSE"):
            raise SystemExit(f"make-sbom: {name} {ver}: workspace must use only the root license_file")
        c["licenses"] = own_license
        continue  # Larsal's own crates use LICENSE, not third-party notices.
    if not p["license"]:
        raise SystemExit(f"make-sbom: {name} {ver}: third-party SPDX license is missing")
    lic = spdx(p["license"])
    c["licenses"] = [{"expression": lic}]
    if p["authors"]:
        c["authors"] = [{"name": a} for a in p["authors"]]
    if p.get("repository"):
        c["externalReferences"] = [{"type": "vcs", "url": p["repository"]}]
    if vendored:
        path, why = patch[name]
        c["pedigree"] = {"ancestors": [{"type": "library", "name": name, "version": ver, "purl": f"pkg:cargo/{name}@{ver}"}],
                         "patches": [{"type": "unofficial"}], "notes": f"{path}: {why}"}
        src = f"Larsal's patched copy, `{path}`"
    else:
        c["purl"], c["hashes"] = f"pkg:cargo/{name}@{ver}", [{"alg": "SHA-256", "content": lock[key]}]
        src = "crates.io"
    rows.append(f"| {name} | {ver} | {lic} | {used} | {src} |")
    files = sorted(f for f in os.listdir(d) if pat.match(f) and os.path.isfile(f"{d}/{f}"))
    for f in files:
        texts.setdefault(norm(open(f"{d}/{f}", errors="replace").read()), []).append(f"{name} {ver} ({f})")
    if all(f.lower().startswith("authors") for f in files):  # the standard text of the first license in the expression that has one here
        std = next(l for l in re.findall(r"[\w.-]+", lic) if l in std_texts)
        texts.setdefault(norm(open(std_texts[std]).read()), []).append(f"{name} {ver} (standard {std} text)")
        missing.append(f"| {name} {ver} | {lic} | {std}; authors: {', '.join(p['authors']) or 'not listed'};"
                       f" source: {p.get('repository') or 'crates.io'} |")

std_ver = rustc.split()[1]
comps.append({"type": "library", "bom-ref": f"rust-std@{std_ver}", "name": "Rust standard library", "version": std_ver,
              "scope": "required", "licenses": [{"expression": "MIT OR Apache-2.0"}],
              "properties": [{"name": "larsal:ships-in", "value": "Larsal.app, larsal"}, {"name": "larsal:rustc", "value": rustc}]})
rows.append(f"| Rust standard library | {std_ver} | MIT OR Apache-2.0, its parts in `rust-std-COPYRIGHT.html` | Larsal.app, larsal | the Rust toolchain |")
shutil.copyfile(f"{sysroot}/share/doc/rust/COPYRIGHT-library.html", f"{out}/rust-std-COPYRIGHT.html")

# The Public Suffix List compiled into larsal-browser (INT-03.19, LD-322 (7)):
# MPL-2.0 data, shipped unchanged; its source form is the file at its commit.
psl_ver = version.get("larsal-browser")
psl_ships = ", ".join(sorted(ships.get(("larsal-browser", psl_ver), set())))
psl_commit = re.search(r"Commit:\s+([0-9a-f]{40})", open("vendor/public-suffix-list/SOURCE.txt").read()).group(1)
if psl_ships:
    comps.append({"type": "data", "bom-ref": f"public-suffix-list@{psl_commit}", "name": "Public Suffix List",
                  "version": psl_commit, "scope": "required", "licenses": [{"expression": "MPL-2.0"}],
                  "properties": [{"name": "larsal:ships-in", "value": psl_ships},
                                 {"name": "larsal:source", "value": "vendor/public-suffix-list/public_suffix_list.dat"}]})
    rows.append(f"| Public Suffix List (data) | {psl_commit[:12]} | MPL-2.0 | {psl_ships} | "
                "https://github.com/publicsuffix/list, `vendor/public-suffix-list/` |")
    texts.setdefault(norm(open("vendor/public-suffix-list/LICENSE").read()), []).append(
        f"Public Suffix List {psl_commit[:12]} (vendor/public-suffix-list/LICENSE)")

app_ref = f"Larsal@{version['larsal-ffi']}"
deps = {app_ref: {f"larsal-cli@{version['larsal-cli']}", f"larsal-ffi@{version['larsal-ffi']}", f"rust-std@{std_ver}"}}
for a, b in edges:
    deps.setdefault(f"{a[0]}@{a[1]}", set()).add(f"{b[0]}@{b[1]}")
if psl_ships:
    deps.setdefault(f"larsal-browser@{psl_ver}", set()).add(f"public-suffix-list@{psl_commit}")
ts = datetime.datetime.fromtimestamp(int(os.environ["SOURCE_DATE_EPOCH"]), datetime.timezone.utc)
bom = {"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
       "metadata": {"timestamp": ts.strftime("%Y-%m-%dT%H:%M:%SZ"), "lifecycles": [{"phase": "build"}],
                    "tools": {"components": [{"type": "application", "name": "scripts/make-sbom.sh"}]},
                    "component": {"type": "application", "bom-ref": app_ref, "name": "Larsal", "version": version["larsal-ffi"],
                                  "licenses": own_license,
                                  "description": "Larsal.app and the larsal command line tool, macOS arm64"}},
       "components": comps,
       "dependencies": [{"ref": r, "dependsOn": sorted(v)} for r, v in sorted(deps.items())]}
with open(f"{out}/sbom.cdx.json", "w") as f:
    json.dump(bom, f, indent=1, sort_keys=True)
    f.write("\n")

md = ["# Third-party notices", "",
       "Larsal and the `larsal` command line tool ship the third-party software below. This file is made by "
       "`scripts/make-sbom.sh` from `Cargo.lock` and the crates' own license files; do not edit it by hand. "
       f"The same list with checksums is `sbom.cdx.json`. Larsal itself is under {license_name}; its text is `LICENSE`, "
       "beside this file in Larsal.app.", "",
       "| Crate | Version | License | Ships in | Source |", "|---|---|---|---|---|", *rows, ""]
words = re.search(r'pub const ATTRIBUTION: &str =\s*"([^"]+)";', open("crates/larsal-core/src/generator/wordlist.rs").read())
if missing:
    md += ["These crates publish no license file; the standard text of the license Larsal uses them under is below.", "",
            "| Crate | License | Text used |", "|---|---|---|", *missing, ""]
md += ["## Built-in word list", "", "Compiled into Larsal.app and `larsal` (larsal-core `generator/wordlist.rs`).", "", words.group(1), ""]
if psl_ships:
    md += ["## Public Suffix List", "",
           f"Compiled into {psl_ships} (larsal-browser `psl.rs`): `public_suffix_list.dat` of "
           f"https://github.com/publicsuffix/list at commit {psl_commit}, unchanged, under the Mozilla Public License 2.0 "
           "(its text is below). That file at that commit is its source form.", ""]
md += ["## License texts", "", "Each text once, after the crates that ship it.", ""]
for i, (t, who) in enumerate(sorted(texts.items(), key=lambda kv: kv[1][0].lower()), 1):
    md += [f"### Text {i}", "", "Used by: " + "; ".join(who) + ".", "", "````text", t, "````", ""]
open(f"{out}/THIRD-PARTY-NOTICES.md", "w").write("\n".join(md))
print(f"make-sbom: {len(comps)} components, {len(texts)} license texts, {len(missing)} crates without a license file")
PY
