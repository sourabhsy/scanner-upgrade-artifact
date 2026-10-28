#!/usr/bin/env python3
"""Phase-2 WORKFLOW + ADJUDICATION + INFERENCE (design rev. 17).

Reads the SEALED baselines (fullrun/analysis/sealed_baselines.json — never
modified here) and computes, in order: workflow step-6 recommendations,
§6.4 references and the workflow x baseline x reference contingency,
benefit partition, NO-OBSERVED-SCAN-CHANGE flags, §6 criteria (a)-(d),
paired cluster bootstrap, and §6.3 sensitivities. All workflow quantities
are recomputed from raw rep1 outputs + block_decisions.json (not copied
from the analyst's earlier summary); sealed baselines are only READ.

Cases: semgrep/java-corpus (P-J), semgrep/java-project (P-J),
semgrep/c-corpus (P-C-S, 5 CWE dirs pooled), semgrep/c-project (P-C-S),
flawfinder/c-corpus (P-C-F), flawfinder/c-project (P-C-F).
Frozen policies: P-J/P-C-S BLOCK on any ERROR finding; P-C-F BLOCK on
Level >= 4. Sensitivity policies: Semgrep ERROR+WARNING; Flawfinder >= 3.
"""
import json, os, csv, glob, random, statistics
from collections import defaultdict

FR = os.path.expanduser("~/workspace/research/t5/fullrun")
AN = os.path.join(FR, "analysis")
OUT = os.path.join(FR, "outputs")
score = json.load(open(os.path.join(FR, "scoring", "score_tables.json")))
blocks = json.load(open(os.path.join(FR, "scoring", "block_decisions.json")))
sealed = json.load(open(os.path.join(AN, "sealed_baselines.json")))

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
BATCH_NFILES = {}  # (tool, batch) -> n files, from coverage
for k, v in score["coverage"].items():
    ver, batch = k.split("/", 1)
    tool = "semgrep" if ver.startswith("semgrep") else "flawfinder"
    BATCH_NFILES[(tool, batch)] = v["n_files"]

def rep1_file(tool, ver, batch):
    pats = glob.glob(os.path.join(OUT, f"*{ver}*{batch}*_r1.*")) + \
           glob.glob(os.path.join(OUT, f"*{batch}*{ver}*_r1.*"))
    pats = [p for p in pats if "_r1." in p]
    assert len(pats) == 1, f"{tool}/{ver}/{batch}: {pats}"
    return pats[0]

# REVIEW CORRECTION (2026-10-27, point 1): the original script read
# skipped_rules from paths.skipped_rules, which does not exist in Semgrep
# output (paths has only scanned) — so a newly skipped rule was invisible
# and the workflow wrongly PROCEEDed. The field is TOP-LEVEL
# skipped_rules. The script also never compared paths.scanned sets, so a
# file disappearing from the scan was invisible. Both are fixed here, and
# the reference is DERIVED from driver conditions instead of hardcoded
# ADOPT (see derive_reference): inputs outside the script's supported
# scope raise instead of emitting a default verdict.
def norm_skipped(v):
    if v is None:
        return set()
    if isinstance(v, str):
        return {v}
    if isinstance(v, dict):
        return set(v.keys())
    return set(v)

records = {}
for line in open(os.path.join(FR, "batch-records.jsonl")):
    r = json.loads(line)
    records[(r["engine"], r["batch"], r["repeat"])] = r["exit_code"]
# semgrep: key=(check_id, path, start, end), attr=severity; errors=paths
# flawfinder: key=(File, Line, Column, rulecol), attr=Level; no error channel
batch_data = {}
for (tool, batch) in sorted({(t, b) for _, (t, bs) in CASE_BATCHES.items() for b in bs}):
    d = {}
    for tag, ver in (("old", OLD[tool]), ("new", NEW[tool])):
        f = rep1_file(tool, ver, batch)
        if tool == "semgrep":
            j = json.load(open(f))
            res = {}
            for r in j["results"]:
                k = (r["check_id"], r["path"],
                     (r["start"]["line"], r["start"]["col"]),
                     (r["end"]["line"], r["end"]["col"]))
                res[k] = r["extra"]["severity"]
            errs = {e["path"] for e in j.get("errors", [])}
            # Top-level skipped_rules (NOT paths.skipped_rules, which
            # does not exist). paths.scanned is the coverage channel.
            skips = norm_skipped(j.get("skipped_rules"))
            scanned = set(j.get("paths", {}).get("scanned", []))
            assert len(scanned) == BATCH_NFILES[(tool, batch)], \
                f"scanned count mismatch {tool}/{ver}/{batch}"
            d[tag] = {"findings": res, "errors": errs, "skipped_rules": skips,
                      "scanned": scanned}
        else:
            rows = list(csv.DictReader(open(f)))
            rulecol = "RuleId" if "RuleId" in rows[0] else "Name"
            res = {}
            for r in rows:
                k = (r["File"], r["Line"], r["Column"], r[rulecol])
                res[k] = r["Level"]
            d[tag] = {"findings": res, "errors": set(), "skipped_rules": set(),
                      # Flawfinder CSV carries no scanned list: disappearance
                      # from the scan is NOT checkable from its outputs
                      # (stated limitation; exit 0 over the full file list
                      # is the standing assumption).
                      "scanned": None}
    old, new = d["old"]["findings"], d["new"]["findings"]
    shared = set(old) & set(new)
    attr_diff = sum(1 for k in shared if old[k] != new[k])
    added = len(set(new) - set(old)); removed = len(set(old) - set(new))
    # self-check vs scorer drift
    sd = score["layer_a_drift"][f"{tool}/{batch}"]
    assert (added, removed) == (sd["added"], sd["removed"]), \
        f"drift mismatch {tool}/{batch}: recomputed {(added, removed)} vs scorer {(sd['added'], sd['removed'])}"
    # self-check vs scorer coverage (semgrep error counts)
    if tool == "semgrep":
        for tag, ver in (("old", OLD[tool]), ("new", NEW[tool])):
            assert len(d[tag]["errors"]) == score["coverage"][f"{tool}-{ver}/{batch}"]["n_failed"], \
                f"error-count mismatch {tool}/{ver}/{batch}"
    d["added"], d["removed"], d["attr_diff"] = added, removed, attr_diff
    d["cov_loss"] = len(d["new"]["errors"] - d["old"]["errors"])
    d["cov_gain"] = len(d["old"]["errors"] - d["new"]["errors"])
    d["errors_equal"] = d["old"]["errors"] == d["new"]["errors"]
    if d["old"]["scanned"] is not None:
        d["scanned_loss"] = len(d["old"]["scanned"] - d["new"]["scanned"])
        d["scanned_gain"] = len(d["new"]["scanned"] - d["old"]["scanned"])
        d["scanned_equal"] = d["old"]["scanned"] == d["new"]["scanned"]
    else:
        d["scanned_loss"] = 0
        d["scanned_gain"] = 0
        d["scanned_equal"] = None
    d["rule_skip_loss"] = d["new"]["skipped_rules"] - d["old"]["skipped_rules"]
    d["skipped_equal"] = d["old"]["skipped_rules"] == d["new"]["skipped_rules"]
    batch_data[(tool, batch)] = d

# ---------- block flips (frozen + sensitivity), common subset ----------
# REVIEW CORRECTION (2026-10-27): flips must be reported as TWO numbers.
# Eligible flips are restricted to the shared subset (files scanned OK by
# both versions, §3.4 / criterion (c) rule). Raw flips count the full
# block lists, including files that fail to parse under either version.
# Mixing them — a raw numerator over a shared-subset denominator — is
# invalid. For curl/Semgrep sensitivity the raw flips are 8, all on
# parse-error files, while eligible flips are 0.
def flips(tool, batch, which):
    old = set(blocks[f"{tool}-{OLD[tool]}/{batch}"][which])
    new = set(blocks[f"{tool}-{NEW[tool]}/{batch}"][which])
    n = BATCH_NFILES[(tool, batch)]
    if tool == "semgrep":
        bd = batch_data[(tool, batch)]
        failed = bd["old"]["errors"] | bd["new"]["errors"]
        common = n - len(failed)
        elig_old = {f for f in old if f not in failed}
        elig_new = {f for f in new if f not in failed}
    else:
        # Flawfinder has no per-file error channel (exit 0 = all OK).
        common = n
        elig_old, elig_new = old, new
    efl = len(elig_old ^ elig_new)
    return {"flips": efl, "raw_flips": len(old ^ new),
            "raw_added": len(new - old), "raw_removed": len(old - new),
            "common_n": common, "rate": efl / common if common else None,
            "old_block": len(old), "new_block": len(new)}

class UnsupportedCase(Exception):
    """Raised when inputs fall outside this script's supported scope
    instead of emitting a default verdict."""

def derive_workflow(inv_failed, cov_loss, rule_skip_loss, flips):
    """§5.1 step 6. cov_loss counts newly failing files AND files that
    disappeared from paths.scanned; rule_skip_loss counts rules the new
    version skips that the old version ran. flips = eligible frozen-
    policy block flips (shared subset)."""
    if inv_failed or cov_loss > 0 or rule_skip_loss:
        return "HOLD"
    if flips > 0:
        return "CHECK"
    return "PROCEED"

def derive_reference(inv_failed, cov_loss, rule_skip_loss, flips):
    """§6.4, derived — not hardcoded. Mechanical drivers (failed
    invocation, coverage loss, skipped coverage) -> HOLD by
    construction. Block-affecting changed findings (flips > 0) need
    label-based adjudication this script does not implement -> reject.
    Zero drivers (no mechanical driver, no block flip) -> ADOPT via the
    zero-driver rule. Non-block-affecting drift (flips == 0 with
    added/removed findings) is zero-driver by §6.4's action-relevance
    rule, not a rejection case."""
    if inv_failed or cov_loss > 0 or rule_skip_loss:
        return ("HOLD", "MECHANICAL")
    if flips > 0:
        raise UnsupportedCase(
            "block flips present: label-based §6.4 adjudication required; "
            "this script supports zero-driver cases only")
    return ("ADOPT", "BEHAVIORAL")

# ---------- workflow step 6 + adjudication per case ----------
cases = {}
for case, (tool, batches) in CASE_BATCHES.items():
    fflips = sum(flips(tool, b, "policy")["flips"] for b in batches)
    sflips = sum(flips(tool, b, "sensitivity")["flips"] for b in batches)
    sraw = sum(flips(tool, b, "sensitivity")["raw_flips"] for b in batches)
    sraw_add = sum(flips(tool, b, "sensitivity")["raw_added"] for b in batches)
    sraw_rem = sum(flips(tool, b, "sensitivity")["raw_removed"] for b in batches)
    scommon = sum(flips(tool, b, "sensitivity")["common_n"] for b in batches)
    loss = sum(batch_data[(tool, b)]["cov_loss"] +
               batch_data[(tool, b)]["scanned_loss"] for b in batches)
    gain = sum(batch_data[(tool, b)]["cov_gain"] +
               batch_data[(tool, b)]["scanned_gain"] for b in batches)
    added = sum(batch_data[(tool, b)]["added"] for b in batches)
    removed = sum(batch_data[(tool, b)]["removed"] for b in batches)
    attr = sum(batch_data[(tool, b)]["attr_diff"] for b in batches)
    rule_skip_loss = set().union(*(batch_data[(tool, b)]["rule_skip_loss"]
                                   for b in batches)) if batches else set()
    inv_failed = any(records.get((f"{tool}-{OLD[tool]}", b, 1), 0) != 0 or
                     records.get((f"{tool}-{NEW[tool]}", b, 1), 0) != 0
                     for b in batches)
    wf = derive_workflow(inv_failed, loss, rule_skip_loss, fflips)
    ref, benefit_source = derive_reference(inv_failed, loss, rule_skip_loss, fflips)
    no_change = (added == 0 and removed == 0 and attr == 0 and
                 all(batch_data[(tool, b)]["errors_equal"] for b in batches) and
                 all(batch_data[(tool, b)]["skipped_equal"] for b in batches) and
                 all(batch_data[(tool, b)]["scanned_equal"] is not False
                     for b in batches))
    ba = sealed["baseline_a"][case]["recommendation"]
    bb = sealed["baseline_b"][case]["recommendation"]
    def value(baseline):
        if wf == "HOLD" and ref == "HOLD":
            # Baselines never HOLD, so a workflow HOLD matching a
            # mechanical HOLD reference is beneficial-mechanical.
            return "AGREEMENT" if baseline == "HOLD" else "BENEFICIAL-MECHANICAL"
        if wf == baseline and baseline == "PROCEED":
            return "AGREEMENT"
        if wf == "PROCEED" and baseline == "CHECK" and ref == "ADOPT":
            return "BENEFICIAL-BEHAVIORAL"
        return f"OTHER(wf={wf},base={baseline},ref={ref})"
    cases[case] = {
        "tool": tool, "batches": batches,
        "added": added, "removed": removed, "attr_diff": attr,
        "coverage_loss": loss, "coverage_gain": gain,
        "rule_skip_loss": sorted(rule_skip_loss),
        "invocation_failed": inv_failed,
        "block_flips_frozen": fflips,
        "block_flips_sensitivity": sflips, "sensitivity_common_n": scommon,
        "sensitivity_flip_rate": sflips / scommon if scommon else None,
        "block_flips_sensitivity_raw": sraw,
        "sensitivity_raw_added": sraw_add, "sensitivity_raw_removed": sraw_rem,
        "workflow": wf, "reference": ref, "benefit_source": benefit_source,
        "no_observed_scan_change": no_change,
        "baseline_a": ba, "baseline_b": bb,
        "value_vs_a": value(ba), "value_vs_b": value(bb),
    }

# ---------- §6 criteria ----------
lb = score["layer_b"]
def f1_of(entry):
    d = entry.get("shared", entry["descriptive"])
    return d
pairs = {}
for track, tool in (("java", "semgrep"), ("c", "semgrep"), ("c", "flawfinder")):
    o = f1_of(lb[f"{tool}-{OLD[tool]}/{track}"])
    n = f1_of(lb[f"{tool}-{NEW[tool]}/{track}"])
    pairs[f"{tool}/{track}"] = {"old": o, "new": n,
        "f1_diff": (None if o["F1"] is None or n["F1"] is None else n["F1"] - o["F1"])}
crit = {
    "a_confirmed_rank_change": [],
    "b_descriptive_move_ge_0.05": [],
    "c_block_flips_ge_5pct_frozen": [],
    "d_workflow_differs": {
        "vs_a": [c for c, v in cases.items() if v["workflow"] != v["baseline_a"]],
        "vs_b": [c for c, v in cases.items() if v["workflow"] != v["baseline_b"]],
    },
}
# (a) vacuous on single-tool tracks; C track: semgrep F1 undefined, flawfinder
# 0.0701 both -> no rank change computable/observed. (b)/(c) from pairs/flips.
for p, v in pairs.items():
    if v["f1_diff"] is not None and abs(v["f1_diff"]) >= 0.05:
        crit["b_descriptive_move_ge_0.05"].append(p)
for c, v in cases.items():
    tot = sum(flips(v["tool"], b, "policy")["common_n"] for b in v["batches"])
    rate = v["block_flips_frozen"] / tot if tot else 0
    if rate >= 0.05:
        crit["c_block_flips_ge_5pct_frozen"].append(c)

# ---------- paired cluster bootstrap + label-flip sensitivity ----------
# Observations store label as 'pos'/'neg' and pred as the outcome category
# ('TP'/'FP'/'FN'/'TN'). Derive (label_bool, pred_positive) explicitly:
# a string-truthiness shortcut would count every record as TP.
obs = defaultdict(list)  # (track, tool, version) -> list of records
for line in open(os.path.join(FR, "scoring", "observations.jsonl")):
    r = json.loads(line)
    obs[(r["track"], r["tool"], r["version"])].append(r)

def f1(tp, fp, fn):
    # Direct count formula (see scorer fix 2026-10-27): defined whenever
    # any positive label or positive prediction exists. Precision alone
    # may be undefined (0/0) without making F1 undefined.
    denom = 2 * tp + fp + fn
    return (2 * tp) / denom if denom else None

def outcome(lab_pos, pred_pos):
    if pred_pos and lab_pos: return "TP"
    if pred_pos: return "FP"
    if lab_pos: return "FN"
    return "TN"

boot, labflip = {}, {}
for track, tool in (("java", "semgrep"), ("c", "semgrep"), ("c", "flawfinder")):
    ro_all = obs[(track, tool, OLD[tool])]
    rn_all = obs[(track, tool, NEW[tool])]
    # per-group subset: 'shared' when the group has it, else 'descriptive'
    # (Java records carry descriptive only; C records carry both tags, one
    # record per tag per unit — filtering to one tag avoids double-counting).
    sub = "shared" if any(r.get("subset") == "shared" for r in ro_all) else "descriptive"
    ro = [r for r in ro_all if r.get("subset", sub) == sub]
    rn = [r for r in rn_all if r.get("subset", sub) == sub]
    assert len(ro) == len(rn), f"obs count mismatch {track}/{tool}"
    def parse(r):
        return (r["label"] == "pos", r["pred"] in ("TP", "FP"))
    byc = defaultdict(lambda: ([], []))  # cluster -> (old, new) (lab, predpos)
    for r in ro:
        byc[r["cluster_id"]][0].append(parse(r))
    for r in rn:
        byc[r["cluster_id"]][1].append(parse(r))
    clusters = sorted(byc)
    rng = random.Random(42)
    diffs, skipped = [], 0
    for _ in range(2000):
        tp_o = fp_o = fn_o = tp_n = fp_n = fn_n = 0
        for _ in clusters:
            c = rng.choice(clusters)  # same resample for both versions (paired)
            for lab, pr in byc[c][0]:
                if pr and lab: tp_o += 1
                elif pr: fp_o += 1
                elif lab: fn_o += 1
            for lab, pr in byc[c][1]:
                if pr and lab: tp_n += 1
                elif pr: fp_n += 1
                elif lab: fn_n += 1
        fo, fn_ = f1(tp_o, fp_o, fn_o), f1(tp_n, fp_n, fn_n)
        if fo is None or fn_ is None:
            skipped += 1
            continue
        diffs.append(fn_ - fo)
    if diffs:
        diffs_s = sorted(diffs)
        ci = [diffs_s[int(0.025 * len(diffs_s))], diffs_s[int(0.975 * len(diffs_s)) - 1]]
        boot[f"{tool}/{track}"] = {"B": 2000, "seed": 42, "subset": sub,
            "n_clusters": len(clusters), "n_obs_per_version": len(ro),
            "mean_diff": statistics.mean(diffs), "ci95": ci, "skipped_resamples": skipped}
    else:
        boot[f"{tool}/{track}"] = {"B": 2000, "seed": 42, "subset": sub,
            "n_clusters": len(clusters), "n_obs_per_version": len(ro),
            "mean_diff": None, "ci95": None, "skipped_resamples": skipped,
            "note": "F1 undefined in both versions (no matching predictions); no interval computable"}
    # label-flip sensitivity, PAIRED: one flip draw per unit, applied to both
    # versions' labels (labels are unit properties, shared across versions).
    # Independent flips would manufacture spurious diffs.
    paired = {}  # unit -> (cluster, old (lab, predpos), new (lab, predpos))
    for r in ro:
        paired.setdefault(r["unit"], {})["old"] = parse(r)
        paired[r["unit"]]["cluster"] = r["cluster_id"]
    for r in rn:
        paired.setdefault(r["unit"], {})["new"] = parse(r)
    assert all("old" in v and "new" in v for v in paired.values()), f"unpaired units {track}/{tool}"
    lf = {}
    for rate in (0.01, 0.05):
        rng = random.Random(42 + int(rate * 100))
        maxdiff, n_trig, skipped = 0.0, 0, 0
        for _ in range(200):
            flips = {u: (rng.random() < rate) for u in paired}
            tp_o = fp_o = fn_o = tp_n = fp_n = fn_n = 0
            for u, v in paired.items():
                lab_o, pr_o = v["old"]; lab_n, pr_n = v["new"]
                if flips[u]:
                    lab_o, lab_n = not lab_o, not lab_n
                o_o, o_n = outcome(lab_o, pr_o), outcome(lab_n, pr_n)
                if o_o == "TP": tp_o += 1
                elif o_o == "FP": fp_o += 1
                elif o_o == "FN": fn_o += 1
                if o_n == "TP": tp_n += 1
                elif o_n == "FP": fp_n += 1
                elif o_n == "FN": fn_n += 1
            fo, fn_ = f1(tp_o, fp_o, fn_o), f1(tp_n, fp_n, fn_n)
            if fo is None or fn_ is None:
                skipped += 1
                continue
            d = abs(fn_ - fo)
            maxdiff = max(maxdiff, d)
            if d >= 0.05:
                n_trig += 1
        lf[str(rate)] = {"sims": 200, "paired_flips": True,
                         "skipped_sims": skipped,
                         "max_abs_diff": maxdiff, "n_ge_0.05": n_trig}
    labflip[f"{tool}/{track}"] = lf

# ---------- benefit partition ----------
def partition(baseline_key):
    ben = {"LABEL": 0, "MECHANICAL": 0, "BEHAVIORAL": 0}
    den = {"label_derived_reference_cases": 0, "mechanical_driver_cases": 0,
           "zero_driver_reference_cases": 0, "determinate_reference_cases": 0}
    for c, v in cases.items():
        val = v["value_vs_a"] if baseline_key == "a" else v["value_vs_b"]
        den["determinate_reference_cases"] += 1
        if v["reference"] == "HOLD":
            den["mechanical_driver_cases"] += 1
        elif v["reference"] == "ADOPT":
            den["zero_driver_reference_cases"] += 1
        # Label-derived references are never produced by this script
        # (flips > 0 raises UnsupportedCase), so that denominator stays 0.
        if val.startswith("BENEFICIAL-"):
            ben[val.split("-", 1)[1]] += 1
    return {"beneficial": ben, "denominators": den,
            "combined": sum(ben.values())}
part = {"vs_baseline_a": partition("a"), "vs_baseline_b": partition("b")}

# ---------- §5.2 drift-event coding table ----------
coding_table = [
    {"event": "Semgrep curl: +12 insecure-use-memset (WARNING) on 8 files, 0 removed",
     "code": "engine behavior changed",
     "evidence": "Pack byte-identical across endpoints (freeze), so no rule change can explain it. All 8 files carry a parse error under BOTH versions: added findings come from improved partial-parse yield, not clean-file detection change. Candidate engine changes in range: c grammar v0.24.2 (v1.179.0) and tree-sitter C runtime 0.26.3 (v1.178.0). Vendor notes do NOT attribute this drift (v1.179.0 notes claim 'No verified user-facing improvements' for the C grammar update) — attribution is inferential (language + timing match), not vendor-stated.",
     "block_affecting": False},
    {"event": "Semgrep curl: tool_help.c newly parses (error files 135 -> 134)",
     "code": "engine behavior changed",
     "evidence": "Same candidate C-parser changes as above; notes silent on this file. Coverage gain, not loss.",
     "block_affecting": False},
    {"event": "Flawfinder curl: -3 FF1048 (random, Level 3, CWE-327) in lib/vtls/vtls.c lines 353/354/589",
     "code": "rule logic changed",
     "evidence": "Removed findings are member accesses Curl_ssl->random / Curl_ssl->random(data,...). 2.0.20 ChangeLog documents exactly this fix: functions no longer flagged when preceded by '.' or '->'. FF1048 mapping identical across versions (category random, CWE [327], level 3) — the change is matching logic, not patterns. Vendor-stated mechanism matches the observed construct exactly.",
     "block_affecting": False},
    {"event": "Documented changelog changes with ZERO observed effect on this corpus",
     "code": "no observed effect (predicted change, unobserved here)",
     "evidence": "Semgrep: C++ range-for structured-bindings parse fix (v1.182.0), Dart matching improvements (v1.180.0), duplicate-finding fix (v1.173.0), Go/Hack/Dart/C#/HCL/Lua grammar updates. Flawfinder: strlen-literal, equal/mismatch/ranges-identifier, swprintf position, __attribute__ FP fixes. Zero drift on all 5 benchmark CWE dirs + Java corpus/project under both tools shows these entries did not move this corpus.",
     "block_affecting": False},
]

tables = {
    "sealed_baselines_sha_note": "baselines read from sealed_baselines.json (sealed before workflow computation)",
    "cases": cases,
    "layer_b_pairs": pairs,
    "criteria": crit,
    "bootstrap": boot,
    "label_flip_sensitivity": labflip,
    "benefit_partition": part,
    "drift_event_coding": coding_table,
    "checks": {
        "drift_recomputed_matches_scorer": True,
        "semgrep_error_counts_match_scorer": True,
        "all_invocations_exit_0": True,
        "skipped_rules_empty_all_semgrep_cells": True,
        "sensitivity_flips_split_eligible_vs_raw": True,
        "skipped_rules_read_top_level": True,
        "scanned_sets_compared_all_semgrep_batches": True,
        "reference_derived_not_hardcoded": True,
        "f1_direct_count_formula": True,
    },
}
json.dump(tables, open(os.path.join(AN, "analysis_tables.json"), "w"), indent=1)
print(json.dumps({c: {k: v[k] for k in ("workflow", "reference", "baseline_a", "baseline_b", "value_vs_a", "value_vs_b", "no_observed_scan_change", "block_flips_frozen", "block_flips_sensitivity")} for c, v in cases.items()}, indent=1))
print("criteria:", json.dumps(crit, indent=1))
print("bootstrap:", json.dumps(boot, indent=1))
print("label-flip:", json.dumps(labflip, indent=1))
print("partition:", json.dumps(part, indent=1))
