#!/usr/bin/env python3
"""Verify the source union against both pinned parents; no network or execution of historical workflows."""
import json
import subprocess
import sys
from pathlib import Path

def git(*args):
    return subprocess.check_output(["git", *args])

def tree(ref):
    entries = {}
    for raw in git("ls-tree", "-r", "-z", ref).split(b"\0"):
        if raw:
            meta, name = raw.split(b"\t", 1)
            mode, kind, sha = meta.decode().split()
            entries[name.decode()] = (mode, kind, sha)
    return entries

def require(ok, message):
    if not ok:
        raise SystemExit(message)

root = Path(git("rev-parse", "--show-toplevel").decode().strip())
import os
os.chdir(root)
m = json.loads(Path("docs/migration/source-convergence.json").read_text())
base, native, managed = (m[k] for k in ("common_ancestor", "native_parent", "managed_parent"))
head = git("rev-parse", "HEAD").decode().strip()
require(git("show", "-s", "--format=%P", head).decode().split() == [managed, native], "FAIL: exact two-parent order")
require(git("merge-base", managed, native).decode().strip() == base, "FAIL: common ancestor")
b, n, g, h = map(tree, (base, native, managed, head))
nd = {p for p in set(b) | set(n) if b.get(p) != n.get(p)}
gd = {p for p in set(b) | set(g) if b.get(p) != g.get(p)}
wf = ".github/workflows/native-hid.yml"
require(nd & gd == {wf}, "FAIL: unexpected overlap")
require(nd - {wf} == {e["path"] for e in m["native_delta"]}, "FAIL: native delta census")
require(gd - {wf} == set(m["managed_delta"]), "FAIL: managed delta census")
expected = g.copy()
for e in m["native_delta"]:
    p = e["path"]
    require(n.get(p) == (e["mode"], "blob", e["sha"]), "FAIL: native mode/blob " + p)
    expected[p] = n[p]
del expected[wf]
for e in m["historical_workflows"]:
    parent = n if e["parent"] == native else g
    require(parent.get(wf) == ("100644", "blob", e["sha"]), "FAIL: historical recipe")
    expected[e["path"]] = parent[wf]
allowed = {"CURRENT_TASK.md", "docs/migration/source-convergence.json", "qualification/verify-source-convergence.py", "qualification/verify-combined-offline.sh"}
require(all(p in h for p in allowed), "FAIL: missing candidate metadata")
require(not any(p.startswith(".github/workflows/") for p in h), "FAIL: active workflow present")
different = {p for p in set(expected) | set(h) if expected.get(p) != h.get(p)}
require(different == allowed, "FAIL: unexpected tree differences: " + repr(sorted(different)))
print("SOURCE_UNION=PASS native=%d managed=%d exact_modes_and_blobs=true active_workflows=0" % (len(nd)-1, len(gd)-1))
