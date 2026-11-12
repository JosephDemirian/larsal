"""Remakes the CRY-05.16 test data of this folder from the downloaded files (story E25-S2).

Usage: python3 -B -I cut.py <downloads> <out>

<downloads> holds the files exactly as fetched (README.md names each URL and commit):
  acvp/<name>.internalProjection.json   usnistgov/ACVP-Server gen-val/json-files/<name>/internalProjection.json
  wycheproof/<name>.json                C2SP/wycheproof testvectors_v1/<name>.json
  composite/draft-composite-sigs-f0627ab.tar.gz   lamps-wg/draft-composite-sigs at f0627ab
  xwing/draft-connolly-cfrg-xwing-kem-11.html     datatracker.ietf.org/doc/html/draft-connolly-cfrg-xwing-kem-11

The cut keeps only the ML-KEM-768 and ML-DSA-65 cases (no pre-hash groups: Larsal has no
HashML-DSA), the composite case id-MLDSA65-Ed25519-SHA512 and Appendix C of X-Wing draft 11,
in one line per record: a kind, then key=value pairs, values in lower-case hex (text fields such as
results and reasons are written as words). A `group` line sets fields for the lines below it.
Nothing is computed: every value is copied from its file. It prints the SHA-256 of every input and
output file.
"""
import base64, hashlib, html, json, re, sys, tarfile
from pathlib import Path

src, out = Path(sys.argv[1]), Path(sys.argv[2])
inputs = []


def load(rel):
    p = src / rel
    inputs.append(p)
    return json.loads(p.read_bytes())


def h(v):
    return v.lower() if v else ""


def line(kind, **kw):
    return kind + "".join(f" {k}={v}" for k, v in kw.items()) + "\n"


def write(name, text):
    (out / name).write_text(text)


# ML-KEM-768, ACVP.
t = "# ACVP ML-KEM-768: keyGen and encapDecap (cut.py)\n"
for g in load("acvp/ML-KEM-keyGen-FIPS203.internalProjection.json")["testGroups"]:
    if g["parameterSet"] == "ML-KEM-768":
        for c in g["tests"]:
            t += line("keygen", tc=c["tcId"], d=h(c["d"]), z=h(c["z"]), ek=h(c["ek"]), dk=h(c["dk"]))
for g in load("acvp/ML-KEM-encapDecap-FIPS203.internalProjection.json")["testGroups"]:
    if g["parameterSet"] != "ML-KEM-768":
        continue
    f = g["function"]
    for c in g["tests"]:
        if f == "encapsulation":
            t += line("encap", tc=c["tcId"], ek=h(c["ek"]), m=h(c["m"]), c=h(c["c"]), k=h(c["k"]))
        elif f == "decapsulation":
            t += line("decap", tc=c["tcId"], dk=h(c["dk"]), c=h(c["c"]), k=h(c["k"]))
        elif f == "decapsulationKeyCheck":
            t += line("dkcheck", tc=c["tcId"], dk=h(c["dk"]), passed=str(c["testPassed"]).lower())
        elif f == "encapsulationKeyCheck":
            t += line("ekcheck", tc=c["tcId"], ek=h(c["ek"]), passed=str(c["testPassed"]).lower())
        else:
            raise SystemExit("unknown ML-KEM function " + f)
write("mlkem768-acvp.txt", t)

# ML-KEM-768, Wycheproof.
t = "# Wycheproof ML-KEM-768 (cut.py)\n"
for name in ["mlkem_768_test", "mlkem_768_encaps_test", "mlkem_768_keygen_seed_test", "mlkem_768_semi_expanded_decaps_test"]:
    for g in load(f"wycheproof/{name}.json")["testGroups"]:
        assert g["parameterSet"] == "ML-KEM-768", name
        for c in g["tests"]:
            kw = {"tc": c["tcId"]}
            for k in ("seed", "ek", "dk", "m", "c", "K"):
                if k in c:
                    kw[k.lower()] = h(c[k])
            kw["result"] = c["result"]
            t += line({"MLKEMTest": "test", "MLKEMEncapsTest": "encaps", "MLKEMKeyGen": "keygen",
                       "MLKEMDecapsValidationTest": "decaps"}[g["type"]], **kw)
write("mlkem768-wycheproof.txt", t)

# ML-DSA-65, ACVP.
t = "# ACVP ML-DSA-65: keyGen, sigGen and sigVer, no pre-hash groups (cut.py)\n"
for g in load("acvp/ML-DSA-keyGen-FIPS204.internalProjection.json")["testGroups"]:
    if g["parameterSet"] == "ML-DSA-65":
        for c in g["tests"]:
            t += line("keygen", tc=c["tcId"], seed=h(c["seed"]), pk=h(c["pk"]), sk=h(c["sk"]))
for g in load("acvp/ML-DSA-sigGen-FIPS204.internalProjection.json")["testGroups"]:
    if g["parameterSet"] != "ML-DSA-65" or g["preHash"] == "preHash":
        continue
    t += line("group", det=str(g["deterministic"]).lower(), iface=g["signatureInterface"], extmu=str(g["externalMu"]).lower())
    for c in g["tests"]:
        kw = {"tc": c["tcId"], "sk": h(c["sk"])}
        for k in ("message", "mu", "context", "rnd"):
            if k in c:
                kw[k] = h(c[k])
        kw["signature"] = h(c["signature"])
        t += line("siggen", **kw)
for g in load("acvp/ML-DSA-sigVer-FIPS204.internalProjection.json")["testGroups"]:
    if g["parameterSet"] != "ML-DSA-65" or g["preHash"] == "preHash":
        continue
    t += line("group", iface=g["signatureInterface"], extmu=str(g["externalMu"]).lower())
    for c in g["tests"]:
        kw = {"tc": c["tcId"], "pk": h(c["pk"])}
        for k in ("message", "mu", "context"):
            if k in c:
                kw[k] = h(c[k])
        kw["signature"] = h(c["signature"])
        kw["passed"] = str(c["testPassed"]).lower()
        t += line("sigver", **kw)
write("mldsa65-acvp.txt", t)

# ML-DSA-65, Wycheproof.
t = "# Wycheproof ML-DSA-65 (cut.py)\n"
for name, kind in [("mldsa_65_verify_test", "verify"), ("mldsa_65_sign_seed_test", "sign")]:
    for g in load(f"wycheproof/{name}.json")["testGroups"]:
        gk = {}
        if "privateSeed" in g:
            gk["seed"] = h(g["privateSeed"])
        if isinstance(g.get("publicKey"), str):
            gk["pk"] = h(g["publicKey"])
        t += line("group", **gk)
        for c in g["tests"]:
            kw = {"tc": c["tcId"]}
            for k in ("msg", "ctx", "mu", "rnd", "sig"):
                if k in c:
                    kw[k] = h(c[k])
            kw["result"] = c["result"]
            t += line(kind, **kw)
write("mldsa65-wycheproof.txt", t)

# The composite case of RFC 10073 Appendix E.
tar_path = src / "composite/draft-composite-sigs-f0627ab.tar.gz"
inputs.append(tar_path)
with tarfile.open(tar_path) as tar:
    assert tar.pax_headers["comment"] == "f0627ab34acfe1aee0abce4bee91ed2b577eab76"
    member = tar.getmember("draft-composite-sigs-f0627ab/src/testvectors.json")
    raw = tar.extractfile(member).read()
print(hashlib.sha256(raw).hexdigest(), "src/testvectors.json inside the tarball")
d = json.loads(raw)
b = lambda v: base64.b64decode(v).hex()
case = [c for c in d["tests"] if c["tcId"] == "id-MLDSA65-Ed25519-SHA512"]
assert len(case) == 1
c = case[0]
t = "# RFC 10073 Appendix E, id-MLDSA65-Ed25519-SHA512 (cut.py)\n"
t += line("composite", m=b(d["m"]), ctx=b(d["ctx"]), pk=b(c["pk"]), sk=b(c["sk"]), s=b(c["s"]), swithcontext=b(c["sWithContext"]))
write("composite-mldsa65-ed25519.txt", t)

# X-Wing draft 11, Appendix C.
p = src / "xwing/draft-connolly-cfrg-xwing-kem-11.html"
inputs.append(p)
page = p.read_text()
start = page.index('<section id="appendix-C">')
end = page.index('<section id="appendix-D">')
blocks = re.findall(r"<pre>(.*?)</pre>", page[start:end], re.S)
t = "# X-Wing draft-connolly-cfrg-xwing-kem-11 Appendix C, provisional (cut.py)\n"
records, key = [], None
for block in blocks:
    for raw_line in html.unescape(block).splitlines():
        parts = raw_line.split()
        if not parts:
            continue
        if re.fullmatch(r"[0-9a-f]+", parts[0]) and raw_line.startswith(" "):
            records[-1][key] += parts[0]
        else:
            key = parts[0]
            if key == "seed":
                records.append({})
            records[-1][key] = parts[1] if len(parts) > 1 else ""
for fields in records:
    assert set(fields) == {"seed", "sk", "pk", "eseed", "ct", "ss"}, fields.keys()
    t += line("xwing", **fields)
assert len(records) == 3, len(records)
write("xwing-draft11.txt", t)

for p in inputs:
    print(hashlib.sha256(p.read_bytes()).hexdigest(), "in ", p.relative_to(src))
for p in sorted(out.glob("*.txt")):
    print(hashlib.sha256(p.read_bytes()).hexdigest(), "out", p.name, p.stat().st_size)
