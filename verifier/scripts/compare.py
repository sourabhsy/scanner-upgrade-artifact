#!/usr/bin/env python3
"""Compare YOUR scan outputs against the published T5 evidence bundle.

Verifies, without the raw reference outputs and without re-running the
scorer/analyzer, that your run reproduces the published experiment:
finding sets, error sets, skipped rules, and block lists (frozen +
sensitivity policies) must match exactly, and the eligible/raw flip
counts per case must match analysis_tables.json. If all of these match,
every downstream number necessarily matches too, because scoring and
analysis are deterministic functions of exactly these inputs.

Path handling: your raw outputs carry absolute paths from YOUR machine.
They are relativized by splitting on "/freeze/" (your checkout root
must therefore be named "freeze", which the driver guarantees), giving
the same "freeze/<checkout>/<relpath>" form the bundle uses. Finding
ORDER inside raw files does not matter: comparisons are on sets, so
running Semgrep with --jobs > 1 (which may reorder findings) is fine.

Usage:
  python3 compare.py --outputs /work/outputs --bundle /bundle
  (also checks rep1 == rep2 sets when rep2 outputs are present)
"""
import argparse, csv, gzip, json, os, sys

def rel(p):
    return "freeze/" + p.split("/freeze/", 1)[1] if "/freeze/" in p else p

def norm_skipped(v):
    # skipped_rules entries are strings when present; stringify dicts so
    # the set comparison never crashes on unhashable entries.
    return {json.dumps(x, sort_keys=True) if isinstance(x, dict) else x for x in (v or [])}

def norm_check_id(cid):
    # Semgrep embeds the config path in check_id
    # (e.g. "...freeze.rules-full.c.lang.security.insecure-use-memset").
    # The original run used one shared rules-full checkout; this package
    # uses rules-old/rules-new, so strip the path prefix up to the rules
    # dir on BOTH sides before comparing. Flawfinder RuleIds have no
    # prefix and pass through unchanged.
    for marker in ("rules-full.", "rules-old.", "rules-new."):
        if marker in cid:
            return cid.split(marker, 1)[1]
    return cid

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
SG_BATCHES = ["sg-java-corpus", "sg-java-project", "sg-c-CWE121", "sg-c-CWE122",
              "sg-c-CWE190", "sg-c-CWE476", "sg-c-CWE78", "sg-c-project"]
FF_BATCHES = ["ff-c-CWE121", "ff-c-CWE122", "ff-c-CWE190", "ff-c-CWE476",
              "ff-c-CWE78", "ff-c-project"]

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--outputs", required=True)
    ap.add_argument("--bundle", required=True)
    a = ap.parse_args()
    fails = []
    skipped = []
    def check(name, ok, detail=""):
        print(("PASS " if ok else "FAIL ") + name + (f" | {detail}" if detail else ""))
        if not ok:
            fails.append(name)
    def skip(name):
        print("SKIP " + name + " (batch not run)")
        skipped.append(name)
    with open(os.path.join(a.bundle, "coverage.json")) as f:
        coverage = json.load(f)
    with open(os.path.join(a.bundle, "block_decisions.json")) as f:
        blocks = json.load(f)
    with open(os.path.join(a.bundle, "analysis_tables.json")) as f:
        tables = json.load(f)
    bfind = {}
    with gzip.open(os.path.join(a.bundle, "findings.jsonl.gz"), "rt") as gz:
        for line in gz:
            r = json.loads(line)
            k = (norm_check_id(r["check_id"]), r["path"], tuple(r["start"]), tuple(r["end"]))
            bfind.setdefault((r["tool"], r["version"], r["batch"]), set()).add(k)
    # Load YOUR outputs (rep1; rep2 if present).
    mine = {}
    for tool, vers in (("semgrep", ("1.172.0", "1.182.0")),
                       ("flawfinder", ("2.0.19", "2.0.20"))):
        batches = SG_BATCHES if tool == "semgrep" else FF_BATCHES
        for ver in vers:
            for batch in batches:
                for rep in (1, 2):
                    ext = "json" if tool == "semgrep" else "csv"
                    f = os.path.join(a.outputs, f"{tool}-{ver}_{batch}_r{rep}.{ext}")
                    if not os.path.exists(f):
                        continue
                    if tool == "semgrep":
                        j = json.load(open(f))
                        s = {(norm_check_id(r["check_id"]), rel(r["path"]),
                              (r["start"]["line"], r["start"]["col"]),
                              (r["end"]["line"], r["end"]["col"])): r["extra"]["severity"]
                             for r in j["results"]}
                        errs = {rel(e["path"]) for e in j["errors"]}
                        sk = norm_skipped(j.get("skipped_rules"))
                    else:
                        rows = list(csv.DictReader(open(f)))
                        s = {(r["RuleId"], rel(r["File"]), (r["Line"], r["Column"]),
                              (r["Line"], r["Column"])): r["Level"] for r in rows}
                        errs, sk = set(), set()
                    mine[(tool, ver, batch, rep)] = (set(s.keys()), errs, sk, s)
    # 1. Finding sets + error sets + skipped rules vs bundle (rep1).
    for (tool, batches) in (("semgrep", SG_BATCHES), ("flawfinder", FF_BATCHES)):
        for ver in (OLD[tool], NEW[tool]):
            for batch in batches:
                m = mine.get((tool, ver, batch, 1))
                if m is None:
                    skip(f"outputs present {tool}-{ver}/{batch}")
                    continue
                keys, errs, sk, _ = m
                check(f"findings {tool}-{ver}/{batch}",
                      keys == bfind.get((tool, ver, batch), set()),
                      f"yours {len(keys)} vs bundle {len(bfind.get((tool, ver, batch), set()))}")
                cov = coverage[f"{tool}-{ver}/{batch}"]
                check(f"errors {tool}-{ver}/{batch}",
                      errs == set(cov["errors"]),
                      f"yours {len(errs)} vs bundle {len(cov['errors'])}")
                check(f"skipped_rules {tool}-{ver}/{batch}",
                      sk == norm_skipped(cov["skipped_rules"]))
    # 2. Block lists recomputed from YOUR findings vs bundle block_decisions.
    def block_list(tool, ver, batch, which):
        _, _, _, s = mine[(tool, ver, batch, 1)]
        out = set()
        # Block lists are per FILE; recompute from findings + policy.
        files = {}
        for (cid, path, st, en), attr in s.items():
            files.setdefault(path, []).append(attr)
        for path, attrs in files.items():
            if tool == "semgrep":
                sev = attrs  # severities of findings on this file
                if which == "policy" and "ERROR" in sev:
                    out.add(path)
                if which == "sensitivity" and ("ERROR" in sev or "WARNING" in sev):
                    out.add(path)
            else:
                if which == "policy" and any(int(x) >= 4 for x in attrs):
                    out.add(path)
                if which == "sensitivity" and any(int(x) >= 3 for x in attrs):
                    out.add(path)
        return out
    for (tool, batches) in (("semgrep", SG_BATCHES), ("flawfinder", FF_BATCHES)):
        for ver in (OLD[tool], NEW[tool]):
            for batch in batches:
                if (tool, ver, batch, 1) not in mine:
                    skip(f"blocks {tool}-{ver}/{batch}")
                    continue
                for which in ("policy", "sensitivity"):
                    ref = {rel(f) for f in blocks[f"{tool}-{ver}/{batch}"][which]}
                    got = block_list(tool, ver, batch, which)
                    check(f"blocks {which} {tool}-{ver}/{batch}", got == ref,
                          f"yours {len(got)} vs bundle {len(ref)}")
    # 3. Eligible/raw flips per case vs analysis_tables.json.
    for case, (tool, batches) in CASE_BATCHES.items():
        if any((tool, OLD[tool], b, 1) not in mine or
               (tool, NEW[tool], b, 1) not in mine for b in batches):
            skip(f"flips {case}")
            continue
        ff = sf = sr = 0
        for b in batches:
            if (tool, OLD[tool], b, 1) not in mine or (tool, NEW[tool], b, 1) not in mine:
                continue
            po = block_list(tool, OLD[tool], b, "policy")
            pn = block_list(tool, NEW[tool], b, "policy")
            so = block_list(tool, OLD[tool], b, "sensitivity")
            sn = block_list(tool, NEW[tool], b, "sensitivity")
            if tool == "semgrep":
                fl = set(coverage[f"{tool}-{OLD[tool]}/{b}"]["errors"]) | \
                     set(coverage[f"{tool}-{NEW[tool]}/{b}"]["errors"])
                po = {f for f in po if f not in fl}
                pn = {f for f in pn if f not in fl}
                so = {f for f in so if f not in fl}
                sn = {f for f in sn if f not in fl}
            ff += len(po ^ pn)
            sf += len(so ^ sn)
            sr += len(block_list(tool, OLD[tool], b, "sensitivity") ^
                      block_list(tool, NEW[tool], b, "sensitivity"))
        v = tables["cases"][case]
        check(f"flips {case}",
              (ff, sf, sr) == (v["block_flips_frozen"], v["block_flips_sensitivity"],
                               v["block_flips_sensitivity_raw"]),
              f"recomputed {(ff, sf, sr)}")
    # 4. Repeatability (only if rep2 outputs exist).
    n_rep2 = 0
    for k, v in list(mine.items()):
        tool, ver, batch, rep = k
        if rep == 2 and (tool, ver, batch, 1) in mine:
            n_rep2 += 1
            check(f"rep1==rep2 {tool}-{ver}/{batch}",
                  v[0] == mine[(tool, ver, batch, 1)][0] and
                  v[1] == mine[(tool, ver, batch, 1)][1])
    if n_rep2 == 0:
        print("NOTE: no rep2 outputs found; repeatability check skipped "
              "(run with --repeats 2 to include it).")
    if fails:
        print(f"\nFAILURES: {fails}")
        sys.exit(1)
    if skipped:
        print(f"\nPARTIAL RUN: all checks for batches present pass; "
              f"{len(skipped)} checks skipped (batches not run). "
              f"Run all batches for the full verification.")
        sys.exit(0)
    print("\nALL COMPARE CHECKS PASS")
    sys.exit(0)

if __name__ == "__main__":
    main()
