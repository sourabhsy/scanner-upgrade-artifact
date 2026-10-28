#!/usr/bin/env python3
"""Build artifact-only replay inputs from the raw full-run outputs.

Writes (into the evidence bundle):
- coverage.json: per (tool, version, batch): FULL scanned / error /
  skipped-rules sets. This supersedes batch-records.jsonl's error_files,
  which the runner truncated to 20 entries (run_full.py:144).
- findings.jsonl.gz: normalized findings (one record per finding, rep1
  only; rep1==rep2 identity is a scorer check, 32/32).

Paths are relativized by stripping everything up to and including
'freeze/' so the artifacts do not depend on the author's workspace
layout; the transform is identical for both versions within a batch,
so all cross-version comparisons are unaffected.
"""
import csv, glob, gzip, json, os

FR = os.path.expanduser("~/workspace/research/t5/fullrun")
OUT = os.path.join(FR, "outputs")
EB = os.path.join(FR, "evidence-bundle")

def rel(p):
    return "freeze/" + p.split("/freeze/", 1)[1] if "/freeze/" in p else p

coverage = {}
for tool, vers in (("semgrep", ("1.172.0", "1.182.0")),
                   ("flawfinder", ("2.0.19", "2.0.20"))):
    batches = sorted({os.path.basename(f).split("_r1.")[0].split(f"{tool}-{vers[0]}_", 1)[1]
                      for f in glob.glob(os.path.join(OUT, f"{tool}-{vers[0]}_*_r1.*"))})
    for batch in batches:
        for ver in vers:
            f = glob.glob(os.path.join(OUT, f"{tool}-{ver}_{batch}_r1.*"))
            assert len(f) == 1, f
            if tool == "semgrep":
                j = json.load(open(f[0]))
                coverage[f"{tool}-{ver}/{batch}"] = {
                    "scanned": sorted(rel(p) for p in j["paths"]["scanned"]),
                    "errors": sorted(rel(e["path"]) for e in j["errors"]),
                    "skipped_rules": sorted(
                        j.get("skipped_rules") or []),
                    "n_files": len(j["paths"]["scanned"]),
                }
            else:
                rows = list(csv.DictReader(open(f[0])))
                coverage[f"{tool}-{ver}/{batch}"] = {
                    "scanned": None,  # CSV carries no scanned list (stated limitation)
                    "errors": [],
                    "skipped_rules": [],
                    "n_files": None,  # filled from batch records below
                }
# flawfinder n_files comes from batch records (file counts), not CSV rows
recs = {}
for line in open(os.path.join(FR, "batch-records.jsonl")):
    r = json.loads(line)
    recs[(r["engine"], r["batch"])] = r["n_files"]
for k in coverage:
    tool, rest = k.split("-", 1)
    ver, batch = rest.split("/", 1)
    if coverage[k]["scanned"] is None:
        coverage[k]["n_files"] = recs[(f"{tool}-{ver}", batch)]
json.dump(coverage, open(os.path.join(EB, "coverage.json"), "w"), indent=0)
print("coverage batches:", len(coverage))

n = 0
with gzip.open(os.path.join(EB, "findings.jsonl.gz"), "wt") as gz:
    for tool, vers in (("semgrep", ("1.172.0", "1.182.0")),
                       ("flawfinder", ("2.0.19", "2.0.20"))):
        for ver in vers:
            for f in sorted(glob.glob(os.path.join(OUT, f"{tool}-{ver}_*_r1.*"))):
                batch = os.path.basename(f).split("_r1.")[0].split(f"{tool}-{ver}_", 1)[1]
                if tool == "semgrep":
                    j = json.load(open(f))
                    for r in j["results"]:
                        gz.write(json.dumps({
                            "tool": tool, "version": ver, "batch": batch,
                            "check_id": r["check_id"], "path": rel(r["path"]),
                            "start": [r["start"]["line"], r["start"]["col"]],
                            "end": [r["end"]["line"], r["end"]["col"]],
                            "severity": r["extra"]["severity"]}) + "\n")
                        n += 1
                else:
                    for r in csv.DictReader(open(f)):
                        gz.write(json.dumps({
                            "tool": tool, "version": ver, "batch": batch,
                            "check_id": r["RuleId"], "path": rel(r["File"]),
                            "start": [r["Line"], r["Column"]],
                            "end": [r["Line"], r["Column"]],
                            "severity": r["Level"]}) + "\n")
                        n += 1
print("findings written:", n)
