#!/usr/bin/env python3
"""Makes weak-key-file and to-key-a for files.rs's tests (C2R2-06, E22-S4).

weak-key-file: a key file under the passphrase "demo key file pass" at work
factor 10, below FIL-03.2's 18, holding the demo identity A of
crates/larsal-files/testdata/make_derived.py. to-key-a: a file to that
identity. Both from make_derived.py's own writing of the format, standard
library only, no Larsal code. Demo data only.

Run with -B -I, with this folder as its one argument.
"""
import importlib.util
import sys
from pathlib import Path

here = Path(sys.argv[1])
spec = importlib.util.spec_from_file_location(
    "make_derived", here / "../../larsal-files/testdata/make_derived.py"
)
d = importlib.util.module_from_spec(spec)
spec.loader.exec_module(d)
d.prove_primitives()

name = "weak_key_file"
key = d.fk(name)
listing = b"# demo identity A\n" + d.TEXT_A.encode() + b"\n"
head = d.seal_header(key, d.s_stanza(name, key, log_n=10, passphrase="demo key file pass"))
(here / "weak-key-file").write_bytes(head + d.payload(key, d.nonce(name), listing))
(here / "to-key-a").write_bytes(d.x_file("to_key_a"))
print("wrote weak-key-file and to-key-a")
