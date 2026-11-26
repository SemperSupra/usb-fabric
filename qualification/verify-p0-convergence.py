#!/usr/bin/env python3
"""Exact Git union of independently qualified P0 source prerequisites."""
import json
import os
import subprocess
from pathlib import Path

def git(*args):
    return subprocess.check_output(["git", *args])

def tree(ref):
    result = {}
    for record in git("ls-tree", "-r", "-z", ref).split(b"\0"):
        if record:
            meta, path = record.split(b"\t", 1)
            result[path.decode()] = tuple(meta.decode().split())
    return result

def require(condition, message):
    if not condition:
        raise SystemExit("P0_SOURCE_UNION_RED " + message)

os.chdir(Path(git("rev-parse", "--show-toplevel").decode().strip()))
m = json.loads(Path("docs/migration/p0-prerequisite-convergence.json").read_text())
base = m["base"]
native, managed = (m["parents"][k] for k in ("native", "managed"))
head = git("rev-parse", "HEAD").decode().strip()
require(git("show", "-s", "--format=%P", head).decode().split() == [native, managed], "two exact parents")
require(git("merge-base", native, managed).decode().strip() == base, "common ancestor")
b, n, g, h = map(tree, (base, native, managed, head))
nd = {p for p in set(b) | set(n) if b.get(p) != n.get(p)}
gd = {p for p in set(b) | set(g) if b.get(p) != g.get(p)}
require(not nd & gd, "unexpected path overlap")
expected = n.copy()
for parent, paths, name in ((n, nd, "native"), (g, gd, "managed")):
    require(paths == {e["path"] for e in m[name]}, name + " delta census")
    for e in m[name]:
        p = e["path"]
        require(parent.get(p) == (e["mode"], "blob", e["sha"]), name + " blob/mode " + p)
        expected[p] = parent[p]
allowed = {"CURRENT_TASK.md", "docs/migration/p0-prerequisite-convergence.json", "qualification/verify-p0-convergence.py"}
require(all(p in h for p in allowed), "missing candidate metadata")
require(not any(p.startswith(".github/workflows/") for p in h), "active workflows")
diff = {p for p in set(expected) | set(h) if expected.get(p) != h.get(p)}
require(diff == allowed, "unexpected tree difference: " + repr(sorted(diff)))
print(f"P0_SOURCE_UNION=PASS native={len(nd)} managed={len(gd)} exact_modes_and_blobs=true active_workflows=0")
