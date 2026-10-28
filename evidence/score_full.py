#!/usr/bin/env python3
"""T5 full-run SCORER (frozen design rev. 17, freeze Amendments 1-3).

Reads ONLY completed full-run outputs (rep1 primary, after verifying
rep1 == rep2 on full identities) + frozen manifests. Writes:
  fullrun/scoring/score_tables.json  (all tables, machine-readable)
  fullrun/scoring/SCORE-REPORT.md    (human-readable tables)
  fullrun/scoring/observations.jsonl (Layer B observation records for bootstrap)
  fullrun/scoring/block_decisions.json (per-file block decisions per cell)

Rules implemented (design §3.4, §3.5, §6.1):
- Layer A: raw drift on canonical identities. Cross-version key EXCLUDES
  severity (semgrep) / Level (flawfinder); repeatability identity KEEPS it.
- Layer B Java: unit = testcase; match = finding in file + rule maps to
  testcase CWE; one TP max per testcase; matching-CWE on non-vulnerable = FP.
- Layer B C: unit = variant; match = finding line within _bad() range
  (inclusive) + rule maps to testcase CWE; matching-CWE in good*() = FP;
  one observation per variant; split files EXCLUDED from Layer B entirely.
- §3.4: per-cell descriptive rates exclude that cell's failed files;
  headline comparisons use the shared subset (files scanned OK in both
  cells); coverage reported separately with the 5% flag; failed files
  never count as zero findings. Flawfinder has no per-file error channel:
  exit 0 over the full file list = all files scanned OK (stated assumption).
- Policies: P-J / P-C-S = BLOCK on any ERROR finding; P-C-F = BLOCK on
  Level >= 4. Sensitivities alongside: semgrep ERROR+WARNING; flawfinder >= 3.
  Block flips only over files with a decision in both cells.
"""
import csv, json, os, re, sys, collections

FZ = os.path.expanduser("~/workspace/research/t5/freeze")
FR = os.path.expanduser("~/workspace/research/t5/fullrun")
OUT = os.path.join(FR, "outputs")
SC = os.path.join(FR, "scoring")
os.makedirs(SC, exist_ok=True)

def load_json(p):
    with open(p) as f:
        return json.load(f)

def rel(path, marker):
    i = path.find(marker)
    assert i >= 0, path
    return path[i + len(marker):]

def cwe_int(s):
    # 'CWE121' / 'CWE-78' / '121' / 121 -> 121
    s = str(s).strip()
    s = re.sub(r"^CWE-?", "", s)
    return int(s)

# ---------------- frozen inputs ----------------
corpus = load_json(os.path.join(FZ, "freeze-corpus-manifest.json"))
variants = load_json(os.path.join(FZ, "freeze-variant-manifest.json"))
clusters = load_json(os.path.join(FZ, "freeze-cluster-manifest.json"))
maps = load_json(os.path.join(FZ, "freeze-rule-cwe-mappings.json"))

java_label = {}   # testcase id -> (vulnerable bool, cwe int, category)
java_cluster = {}
c_items = {}      # rel path -> manifest item
for it in corpus["items"]:
    if it["track"] == "java":
        lab = it["label"]
        java_label[it["id"]] = (bool(lab["vulnerable"]), cwe_int(lab["cwe"]), lab["category"])
    elif it["track"] == "c":
        c_items[it["id"]] = it
for ci in clusters["items"]:
    if ci["track"] == "java":
        java_cluster[ci["id"]] = ci["cluster_id"]

sg_maps = maps["semgrep"]
assert maps.get("semgrep_identical") is True, "semgrep mapping tables differ across engines"
sg_map = {r: [int(c) for c in rec.get("cwes") or []] for r, rec in sg_maps["1.172.0"].items()}
ff_maps = maps["flawfinder"]
ff_map = {}
for ver, table in ff_maps.items():
    if ver in ("2.0.19", "2.0.20"):
        ff_map[ver] = {r: [int(c) for c in rec.get("cwes") or []] for r, rec in table.items()}

var_by_id = {}
for e in variants["variants"]:
    var_by_id[e["id"]] = e
assert variants["totals"]["positive_observations"] == 9718
assert variants["totals"]["negative_observations"] == 31549
assert variants["totals"]["excluded"] == 10856

# ---------------- output loading ----------------
def sg_load(engine, batch, rep):
    d = load_json(os.path.join(OUT, f"{engine}_{batch}_r{rep}.json"))
    assert d.get("skipped_rules") == [], (engine, batch, rep, d.get("skipped_rules"))
    return d

def ff_load(engine, batch, rep):
    rows = []
    with open(os.path.join(OUT, f"{engine}_{batch}_r{rep}.csv"), newline="") as f:
        for row in csv.DictReader(f):
            rows.append(row)
    return rows

def sg_xkey(r):
    s, e = r["start"], r["end"]
    return (r["check_id"], r["path"], s["line"], s["col"], e["line"], e["col"])

def sg_fkey(r):
    return sg_xkey(r) + (r.get("extra", {}).get("severity", ""),)

def ff_xkey(r):
    return (r["File"], int(r["Line"]), int(r["Column"]), r["RuleId"])

def ff_fkey(r):
    return ff_xkey(r) + (int(r["Level"]),)

def ff_cwes(r):
    # CWEs field mixes separators (',', '/') and '!' markers
    # (e.g. 'CWE-119!/CWE-120'); extract every CWE number present.
    return [int(n) for n in re.findall(r"CWE-?(\d+)", r.get("CWEs") or "")]

BATCHES_SG = ["sg-java-corpus", "sg-java-project", "sg-c-CWE121", "sg-c-CWE122",
              "sg-c-CWE190", "sg-c-CWE476", "sg-c-CWE78", "sg-c-project"]
BATCHES_FF = ["ff-c-CWE121", "ff-c-CWE122", "ff-c-CWE190", "ff-c-CWE476", "ff-c-CWE78", "ff-c-project"]

report = {"repeatability": {}, "coverage": {}, "layer_a_drift": {}, "layer_b": {},
          "blocks": {}, "checks": []}
def check(name, ok, detail=""):
    report["checks"].append({"check": name, "pass": bool(ok), "detail": detail})
    print(("PASS " if ok else "FAIL ") + name + (" | " + detail if detail else ""))

# ---------------- 1. repeatability + coverage ----------------
cells = {}  # (tool, version, batch) -> {results, errors, files}
for engine, batches, loader in [("semgrep-1.172.0", BATCHES_SG, "sg"),
                                ("semgrep-1.182.0", BATCHES_SG, "sg"),
                                ("flawfinder-2.0.19", BATCHES_FF, "ff"),
                                ("flawfinder-2.0.20", BATCHES_FF, "ff")]:
    tool, ver = engine.split("-", 1) if False else (engine.split("-")[0], engine.split("-", 1)[1])
    for batch in batches:
        if loader == "sg":
            d1, d2 = sg_load(engine, batch, 1), sg_load(engine, batch, 2)
            r1 = [sg_fkey(r) for r in d1["results"]]
            r2 = [sg_fkey(r) for r in d2["results"]]
            e1 = {e.get("path", "") for e in d1["errors"]}
            e2 = {e.get("path", "") for e in d2["errors"]}
            err_msgs = collections.Counter()
            for e in d1["errors"]:
                m = e.get("message", "")
                m = re.sub(r" at line .*", " at line <path>", m.split("\n")[0])
                err_msgs[m[:80]] += 1
            cells[(tool, ver, batch)] = {"results": d1["results"], "errors": d1["errors"],
                                         "err_files": e1, "err_msgs": dict(err_msgs)}
        else:
            rows1, rows2 = ff_load(engine, batch, 1), ff_load(engine, batch, 2)
            r1 = [ff_fkey(r) for r in rows1]
            r2 = [ff_fkey(r) for r in rows2]
            cells[(tool, ver, batch)] = {"results": rows1, "errors": [],
                                         "err_files": set(), "err_msgs": {}}
        same = (collections.Counter(r1) == collections.Counter(r2))
        if loader == "sg":
            same = same and (e1 == e2)
        report["repeatability"][f"{engine}/{batch}"] = {
            "rep1_n": len(r1), "rep2_n": len(r2), "identical": same}
        if not same:
            print(f"REPEAT DIFF {engine} {batch}: rep1-only={len(set(r1)-set(r2))} "
                  f"rep2-only={len(set(r2)-set(r1))}")

# batch file counts from corpus manifest
batch_files = collections.defaultdict(set)
for it in corpus["items"]:
    tr = it["track"]
    if tr == "java":
        batch_files["sg-java-corpus"].add(it["id"])
    elif tr == "project-java":
        batch_files["sg-java-project"].add(it["id"])
    elif tr == "c":
        batch_files[f"sg-c-{it['cwe']}"].add(it["id"])
        batch_files[f"ff-c-{it['cwe']}"].add(it["id"])
    elif tr == "project-c":
        batch_files["sg-c-project"].add(it["id"])
        batch_files["ff-c-project"].add(it["id"])

for (tool, ver, batch), cell in sorted(cells.items()):
    n_files = len(batch_files[batch])
    n_failed = len(cell["err_files"])
    rate = n_failed / n_files if n_files else 0
    report["coverage"][f"{tool}-{ver}/{batch}"] = {
        "n_files": n_files, "n_failed": n_failed, "fail_rate": round(rate, 4),
        "flag_5pct": rate > 0.05, "reasons": cell["err_msgs"]}

# ---------------- 2. Layer A drift ----------------
def drift(tool, old_ver, new_ver, batch):
    old = cells[(tool, old_ver, batch)]
    new = cells[(tool, new_ver, batch)]
    if tool == "semgrep":
        A = {sg_xkey(r) for r in old["results"]}
        B = {sg_xkey(r) for r in new["results"]}
        rule = lambda k: k[0].split(".")[-1]
    else:
        A = {ff_xkey(r) for r in old["results"]}
        B = {ff_xkey(r) for r in new["results"]}
        rule = lambda k: k[3]
    added = B - A
    removed = A - B
    return {"old_n": len(A), "new_n": len(B), "shared": len(A & B),
            "added": len(added), "removed": len(removed),
            "added_by_rule": dict(collections.Counter(rule(k) for k in added).most_common(10)),
            "removed_by_rule": dict(collections.Counter(rule(k) for k in removed).most_common(10))}

for batch in BATCHES_SG:
    report["layer_a_drift"][f"semgrep/{batch}"] = drift("semgrep", "1.172.0", "1.182.0", batch)
for batch in BATCHES_FF:
    report["layer_a_drift"][f"flawfinder/{batch}"] = drift("flawfinder", "2.0.19", "2.0.20", batch)

# ---------------- 3. Blocks + flips ----------------
def sg_block_files(cell):
    return {r["path"] for r in cell["results"] if r.get("extra", {}).get("severity") == "ERROR"}

def sg_block_files_sens(cell):
    return {r["path"] for r in cell["results"]
            if r.get("extra", {}).get("severity") in ("ERROR", "WARNING")}

def ff_block_files(cell):
    return {r["File"] for r in cell["results"] if int(r["Level"]) >= 4}

def ff_block_files_sens(cell):
    return {r["File"] for r in cell["results"] if int(r["Level"]) >= 3}

block_decisions = {}
for batch in BATCHES_SG:
    for ver, fn, sfn in [("1.172.0", sg_block_files, sg_block_files_sens),
                         ("1.182.0", sg_block_files, sg_block_files_sens)]:
        cell = cells[("semgrep", ver, batch)]
        block_decisions[f"semgrep-{ver}/{batch}"] = {
            "policy": sorted(fn(cell)), "sensitivity": sorted(sfn(cell)),
            "n_files": len(batch_files[batch])}
    # flips on common-decision files (no error in either version).
    # Flips can only occur on files blocking in at least one cell; all other
    # manifest files are pass/pass. Common-decision count = manifest files
    # minus files failing in either version (error paths are all batch files,
    # so the count subtraction is exact).
    e_old = cells[("semgrep", "1.172.0", batch)]["err_files"]
    e_new = cells[("semgrep", "1.182.0", batch)]["err_files"]
    b_old = sg_block_files(cells[("semgrep", "1.172.0", batch)])
    b_new = sg_block_files(cells[("semgrep", "1.182.0", batch)])
    cand = (b_old | b_new)
    # a candidate flip file with an error in either version has no decision
    # in that cell -> excluded from flips, counted separately
    excluded = {f for f in cand if f in e_old or f in e_new}
    flips = {f for f in cand - excluded if (f in b_old) != (f in b_new)}
    report["blocks"][f"semgrep/{batch}"] = {
        "policy_old_n": len(b_old), "policy_new_n": len(b_new),
        "flips_newly_blocked": sorted(f for f in flips if f in b_new),
        "flips_newly_unblocked": sorted(f for f in flips if f in b_old),
        "flip_excluded_error_files": len(excluded),
        "n_manifest_files": len(batch_files[batch]),
        "n_common_decision_files": len(batch_files[batch]) - len(e_old | e_new)}
for batch in BATCHES_FF:
    for ver, fn, sfn in [("2.0.19", ff_block_files, ff_block_files_sens),
                         ("2.0.20", ff_block_files, ff_block_files_sens)]:
        cell = cells[("flawfinder", ver, batch)]
        block_decisions[f"flawfinder-{ver}/{batch}"] = {
            "policy": sorted(fn(cell)), "sensitivity": sorted(sfn(cell)),
            "n_files": len(batch_files[batch])}
    b_old = ff_block_files(cells[("flawfinder", "2.0.19", batch)])
    b_new = ff_block_files(cells[("flawfinder", "2.0.20", batch)])
    report["blocks"][f"flawfinder/{batch}"] = {
        "policy_old_n": len(b_old), "policy_new_n": len(b_new),
        "flips_newly_blocked": sorted(f for f in (b_new - b_old)),
        "flips_newly_unblocked": sorted(f for f in (b_old - b_new)),
        "flip_excluded_error_files": 0,
        "n_manifest_files": len(batch_files[batch]),
        "n_common_decision_files": len(batch_files[batch])}

json.dump(block_decisions, open(os.path.join(SC, "block_decisions.json"), "w"), indent=1)

# ---------------- 4. Layer B ----------------
obs_records = []
def layer_b_java(tool, ver):
    cell = cells[(tool, ver, "sg-java-corpus")]
    by_file = collections.defaultdict(list)
    for r in cell["results"]:
        fid = os.path.basename(r["path"])[:-5]
        by_file[fid].append(r)
    tp = fp = fn = tn = 0
    for fid, (vuln, cwe, cat) in java_label.items():
        matched = False
        for r in by_file.get(fid, []):
            rule = r["check_id"].split(".")[-1]
            if cwe in sg_map.get(rule, []):
                matched = True
                break
        if vuln and matched:
            tp += 1; pred = "TP"
        elif vuln:
            fn += 1; pred = "FN"
        elif matched:
            fp += 1; pred = "FP"
        else:
            tn += 1; pred = "TN"
        obs_records.append({"track": "java", "tool": tool, "version": ver,
                            "subset": "descriptive", "cluster_id": java_cluster.get(fid),
                            "unit": fid, "label": "pos" if vuln else "neg", "pred": pred})
    return {"TP": tp, "FP": fp, "FN": fn, "TN": tn}

def layer_b_c(tool, ver, err_files_other=None):
    # err_files_other: error set of the OTHER version (for shared subset)
    # gather findings per file across the 5 CWE batches (projects excluded)
    by_file = collections.defaultdict(list)
    err_here = set()
    cwe_dirs = ["CWE121", "CWE122", "CWE190", "CWE476", "CWE78"]
    if tool == "semgrep":
        for d in cwe_dirs:
            c = cells[(tool, ver, f"sg-c-{d}")]
            err_here |= c["err_files"]
            for r in c["results"]:
                fid = rel(r["path"], "juliet-full/testcases/")
                by_file[fid].append(("sg", r))
    else:
        for d in cwe_dirs:
            c = cells[(tool, ver, f"ff-c-{d}")]
            for r in c["results"]:
                fid = rel(r["File"], "juliet-full/testcases/")
                by_file[fid].append(("ff", r))
    def rule_cwes(kind, r):
        if kind == "sg":
            return sg_map.get(r["check_id"].split(".")[-1], [])
        return ff_cwes(r)
    def line_of(kind, r):
        return r["start"]["line"] if kind == "sg" else int(r["Line"])
    out = {}
    for subset, excl in [("descriptive", err_here),
                         ("shared", err_here | (err_files_other or set()))]:
        tp = fp = fn = tn = 0
        for fid, entry in var_by_id.items():
            if entry["split"]:
                continue
            # error-file exclusion: file failed -> variants excluded
            # err paths are absolute freeze paths ending in the rel fid
            if any(p.endswith("testcases/" + fid) for p in excl):
                continue
            tcwe = cwe_int(entry["cwe"])
            findings = by_file.get(fid, [])
            # bad variant
            matched = any(entry["bad"]["start"] <= line_of(k, r) <= entry["bad"]["end"] and
                          tcwe in rule_cwes(k, r) for k, r in findings)
            if matched:
                tp += 1; pred = "TP"
            else:
                fn += 1; pred = "FN"
            obs_records.append({"track": "c", "tool": tool, "version": ver,
                                "subset": subset, "cluster_id": entry["cluster_id"],
                                "unit": fid + "#bad", "label": "pos", "pred": pred})
            for g in entry["good"]:
                matched = any(g["start"] <= line_of(k, r) <= g["end"] and
                              tcwe in rule_cwes(k, r) for k, r in findings)
                if matched:
                    fp += 1; pred = "FP"
                else:
                    tn += 1; pred = "TN"
                obs_records.append({"track": "c", "tool": tool, "version": ver,
                                    "subset": subset, "cluster_id": entry["cluster_id"],
                                    "unit": fid + "#" + g["function"],
                                    "label": "neg", "pred": pred})
        out[subset] = {"TP": tp, "FP": fp, "FN": fn, "TN": tn}
    return out

# error sets per semgrep version (absolute paths)
def sg_err_all(ver):
    s = set()
    for d in ["CWE121", "CWE122", "CWE190", "CWE476", "CWE78"]:
        s |= cells[("semgrep", ver, f"sg-c-{d}")]["err_files"]
    return s

report["layer_b"]["semgrep-1.172.0/java"] = {"descriptive": layer_b_java("semgrep", "1.172.0")}
report["layer_b"]["semgrep-1.182.0/java"] = {"descriptive": layer_b_java("semgrep", "1.182.0")}
report["layer_b"]["semgrep-1.172.0/c"] = layer_b_c("semgrep", "1.172.0",
                                                  err_files_other=sg_err_all("1.182.0"))
report["layer_b"]["semgrep-1.182.0/c"] = layer_b_c("semgrep", "1.182.0",
                                                  err_files_other=sg_err_all("1.172.0"))
report["layer_b"]["flawfinder-2.0.19/c"] = layer_b_c("flawfinder", "2.0.19")
report["layer_b"]["flawfinder-2.0.20/c"] = layer_b_c("flawfinder", "2.0.20")

def prf(t):
    tp, fp, fn, tn = t["TP"], t["FP"], t["FN"], t["TN"]
    p = tp / (tp + fp) if tp + fp else None
    r = tp / (tp + fn) if tp + fn else None
    # REVIEW CORRECTION (2026-10-27): F1 is computed DIRECTLY from counts,
    # 2TP / (2TP + FP + FN). The previous P/R-composed formula returned
    # undefined whenever P or R was zero (e.g. TP=0, FP=1, FN=1, where both
    # are defined as zero) and whenever P was undefined (TP=0, FP=0) even
    # though F1 = 0 is defined. Precision alone stays undefined at 0/0;
    # that does not make F1 undefined.
    denom = 2 * tp + fp + fn
    f = (2 * tp) / denom if denom else None
    return {"P": p, "R": r, "F1": f}

for k, v in report["layer_b"].items():
    for subset, t in v.items():
        v[subset].update(prf(t))

# flawfinder cross-check: reported CWEs vs frozen mapping table (per version)
ff_mismatch = {}
for ver in ("2.0.19", "2.0.20"):
    mism = 0
    tot = 0
    for batch in BATCHES_FF:
        for r in cells[("flawfinder", ver, batch)]["results"]:
            tot += 1
            if set(ff_cwes(r)) != set(ff_map[ver].get(r["RuleId"], [])):
                mism += 1
    ff_mismatch[ver] = {"findings": tot, "mismatched": mism}
report["flawfinder_mapping_crosscheck"] = ff_mismatch
print("flawfinder reported-CWE vs mapping mismatches:", ff_mismatch)

# ---------------- 5. checks ----------------
recs = {}
for line in open(os.path.join(FR, "batch-records.jsonl")):
    r = json.loads(line)
    recs[(r["engine"], r["batch"], r["repeat"])] = r
for (tool, ver, batch), cell in sorted(cells.items()):
    engine = f"{tool}-{ver}"
    n = len(cell["results"])
    check(f"results reconcile {engine}/{batch}",
          recs[(engine, batch, 1)]["n_results"] == n,
          f"record={recs[(engine, batch, 1)]['n_results']} scored={n}")
check("java TP+FN == 1415 (1.172.0)",
      report["layer_b"]["semgrep-1.172.0/java"]["descriptive"]["TP"] +
      report["layer_b"]["semgrep-1.172.0/java"]["descriptive"]["FN"] == 1415)
check("java FP+TN == 1325 (1.172.0)",
      report["layer_b"]["semgrep-1.172.0/java"]["descriptive"]["FP"] +
      report["layer_b"]["semgrep-1.172.0/java"]["descriptive"]["TN"] == 1325)
check("c positives reconcile (shared, semgrep)",
      report["layer_b"]["semgrep-1.172.0/c"]["shared"]["TP"] +
      report["layer_b"]["semgrep-1.172.0/c"]["shared"]["FN"] <= 9718,
      f"shared pos obs={report['layer_b']['semgrep-1.172.0/c']['shared']['TP'] + report['layer_b']['semgrep-1.172.0/c']['shared']['FN']}")
check("all repeat pairs identical",
      all(v["identical"] for v in report["repeatability"].values()))

with open(os.path.join(SC, "observations.jsonl"), "w") as f:
    for o in obs_records:
        f.write(json.dumps(o) + "\n")
json.dump(report, open(os.path.join(SC, "score_tables.json"), "w"), indent=1)
print(f"\nwrote {len(obs_records)} observation records")
print("checks:", sum(1 for c in report["checks"] if c["pass"]), "/",
      len(report["checks"]), "passed")
for c in report["checks"]:
    if not c["pass"]:
        print("FAILED CHECK:", c)
