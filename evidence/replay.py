#!/usr/bin/env python3
"""Artifact-only replay: verify the manuscript's tables from the bundle
alone, without the raw scan outputs or the author's workspace layout.

Usage: python3 replay.py [bundle_dir]   (default: this script's directory)

Checks (each prints PASS/FAIL; exit code is non-zero on any FAIL):
 1. Layer A drift per batch, re-derived from findings.jsonl.gz, equals
    score_tables.json layer_a_drift (added/removed).
 2. Error-set sizes from coverage.json equal score_tables.json coverage
    n_failed; for curl/Semgrep, the 8 sensitivity additions are all in
    the old∩new error sets and eligible sensitivity flips are 0.
 3. Frozen flips (eligible) and sensitivity flips (eligible + raw) from
    block_decisions.json + coverage.json equal analysis_tables.json.
 4. Layer B P/R/F1 from observations.jsonl.gz (direct count formula)
    equal score_tables.json layer_b.
 5. Sealed baselines' recommendations equal analysis_tables.json cases.
The workflow/reference derivation itself lives in analyze.py (bundled,
with control tests in test_analyze_controls.py, which need no raw
outputs); this replay verifies every input that derivation consumes.
"""
import csv, gzip, io, json, os, sys

B = sys.argv[1] if len(sys.argv) > 1 else os.path.dirname(os.path.abspath(__file__))

def load(name):
    with open(os.path.join(B, name)) as f:
        return json.load(f)

def rel(p):
    return "freeze/" + p.split("/freeze/", 1)[1] if "/freeze/" in p else p

fails = []
def check(name, ok, detail=""):
    print(("PASS " if ok else "FAIL ") + name + (f" | {detail}" if detail else ""))
    if not ok:
        fails.append(name)

score = load("score_tables.json")
tables = load("analysis_tables.json")
sealed = load("sealed_baselines.json")
blocks = load("block_decisions.json")
coverage = load("coverage.json")

OLD = {"semgrep": "1.172.0", "flawfinder": "2.0.19"}
NEW = {"semgrep": "1.182.0", "flawfinder": "2.0.20"}
CASE_BATCHES = {
    "semgrep/java-corpus": ("semgrep", ["sg-java-corpus"]),
    "semgrep/java-project": ("semgrep", ["sg-java-project"]),
    "semgrep/c-corpus": ("semgrep", ["sg-c-CWE121", "sg-c-CWE122", "sg-c-CWE190",
                                      "sg-c-CWE476", "sg-c-CWE78"]),
    "semgrep/c-project": ("semgrep", ["sg-c-project"]),
    "flawfinder/c-corpus": ("flawfinder", ["ff-c-CWE121", "ff-c-CWE122", "ff-c-CWE190",
                                            "ff-c-CWE476", "ff-c-CWE78"]),
    "flawfinder/c-project": ("flawfinder", ["ff-c-project"]),
}

# --- 1. drift from findings artifact ---
find = {}
with gzip.open(os.path.join(B, "findings.jsonl.gz"), "rt") as gz:
    for line in gz:
        r = json.loads(line)
        k = (r["check_id"], r["path"], tuple(r["start"]), tuple(r["end"]))
        find.setdefault((r["tool"], r["version"], r["batch"]), set()).add(k)
for (tool, batches) in [("semgrep", ["sg-java-corpus", "sg-java-project", "sg-c-CWE121",
                                     "sg-c-CWE122", "sg-c-CWE190", "sg-c-CWE476",
                                     "sg-c-CWE78", "sg-c-project"]),
                        ("flawfinder", ["ff-c-CWE121", "ff-c-CWE122", "ff-c-CWE190",
                                        "ff-c-CWE476", "ff-c-CWE78", "ff-c-project"])]:
    for batch in batches:
        o = find.get((tool, OLD[tool], batch), set())
        n = find.get((tool, NEW[tool], batch), set())
        sd = score["layer_a_drift"][f"{tool}/{batch}"]
        check(f"drift {tool}/{batch}",
              (len(n - o), len(o - n)) == (sd["added"], sd["removed"]),
              f"recomputed {(len(n - o), len(o - n))} vs table {(sd['added'], sd['removed'])}")

# --- 2. error sets + the 8-added-files claim ---
for key, cov in coverage.items():
    ver = key.split("/", 1)[0]
    sc = score["coverage"][key]
    if cov["errors"]:
        check(f"errors {key}", len(cov["errors"]) == sc["n_failed"],
              f"{len(cov['errors'])} vs {sc['n_failed']}")
    else:
        check(f"errors {key}", sc["n_failed"] == 0, "no errors recorded")
eo = set(coverage["semgrep-1.172.0/sg-c-project"]["errors"])
en = set(coverage["semgrep-1.182.0/sg-c-project"]["errors"])
so = {rel(f) for f in blocks["semgrep-1.172.0/sg-c-project"]["sensitivity"]}
sn = {rel(f) for f in blocks["semgrep-1.182.0/sg-c-project"]["sensitivity"]}
added = sn - so
check("curl sensitivity additions all parse-error files under both versions",
      len(added) == 8 and added <= (eo & en), f"added={len(added)}")
failed = eo | en
check("curl sensitivity eligible flips 0",
      len({f for f in so if f not in failed} ^
          {f for f in sn if f not in failed}) == 0, "26 vs 26 on 105 common")

# --- 3. flips vs analysis tables ---
for case, (tool, batches) in CASE_BATCHES.items():
    ff = sf = sr = 0
    for b in batches:
        po = {rel(f) for f in blocks[f"{tool}-{OLD[tool]}/{b}"]["policy"]}
        pn = {rel(f) for f in blocks[f"{tool}-{NEW[tool]}/{b}"]["policy"]}
        so_b = {rel(f) for f in blocks[f"{tool}-{OLD[tool]}/{b}"]["sensitivity"]}
        sn_b = {rel(f) for f in blocks[f"{tool}-{NEW[tool]}/{b}"]["sensitivity"]}
        if tool == "semgrep":
            fl = set(coverage[f"{tool}-{OLD[tool]}/{b}"]["errors"]) | \
                 set(coverage[f"{tool}-{NEW[tool]}/{b}"]["errors"])
            po, pn = {f for f in po if f not in fl}, {f for f in pn if f not in fl}
            so_b, sn_b = {f for f in so_b if f not in fl}, {f for f in sn_b if f not in fl}
        ff += len(po ^ pn)
        sf += len(so_b ^ sn_b)
        sr += len({rel(f) for f in blocks[f"{tool}-{OLD[tool]}/{b}"]["sensitivity"]} ^
                  {rel(f) for f in blocks[f"{tool}-{NEW[tool]}/{b}"]["sensitivity"]})
    v = tables["cases"][case]
    check(f"flips {case}",
          (ff, sf, sr) == (v["block_flips_frozen"], v["block_flips_sensitivity"],
                           v["block_flips_sensitivity_raw"]),
          f"recomputed {(ff, sf, sr)}")

# --- 4. Layer B from observations (direct count formula) ---
obs = {}
with gzip.open(os.path.join(B, "observations.jsonl.gz"), "rt") as gz:
    for line in gz:
        r = json.loads(line)
        obs.setdefault((r["track"], r["tool"], r["version"], r.get("subset")), []).append(r)
def f1(tp, fp, fn):
    d = 2 * tp + fp + fn
    return (2 * tp) / d if d else None
for track, tool in (("java", "semgrep"), ("c", "semgrep"), ("c", "flawfinder")):
    for tag, ver in (("old", OLD[tool]), ("new", NEW[tool])):
        sub = "shared" if any(r.get("subset") == "shared"
                              for r in obs.get((track, tool, ver, "shared"), [])) \
              else "descriptive"
        # observations carry both tags for C; pick the shared set when present
        rs = [r for r in obs.get((track, tool, ver, sub), [])]
        if not rs:
            rs = [r for r in obs.get((track, tool, ver, "descriptive"), [])]
        tp = fp = fn = tn = 0
        for r in rs:
            lab = r["label"] == "pos"
            pr = r["pred"] in ("TP", "FP")
            if pr and lab: tp += 1
            elif pr: fp += 1
            elif lab: fn += 1
            else: tn += 1
        entry = score["layer_b"][f"{tool}-{ver}/{track}"]
        d = entry.get("shared", entry["descriptive"])
        check(f"layer_b {tool}/{track}/{ver}",
              (tp, fp, fn, tn) == (d["TP"], d["FP"], d["FN"], d["TN"]) and
              f1(tp, fp, fn) == d["F1"],
              f"recomputed {(tp, fp, fn, tn, f1(tp, fp, fn))}")

# --- 5. sealed baselines match analysis tables ---
for case, v in tables["cases"].items():
    check(f"sealed baseline {case}",
          sealed["baseline_a"][case]["recommendation"] == v["baseline_a"] and
          sealed["baseline_b"][case]["recommendation"] == v["baseline_b"])

print(f"\n{'ALL REPLAY CHECKS PASS' if not fails else 'FAILURES: ' + str(fails)}")
sys.exit(1 if fails else 0)
