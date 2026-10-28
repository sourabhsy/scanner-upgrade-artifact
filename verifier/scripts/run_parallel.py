#!/usr/bin/env python3
"""T5 full experiment — PARALLEL SCAN RUNNER (verifier edition).

Same frozen engines/packs/corpus, same batch definitions, same output
format and batch-record fields as the original run_full.py — but:
  - Semgrep runs with --jobs <J> (default: container/host CPU count)
    instead of the original --jobs 1 (a 2-core-VM workaround).
  - Invocations run concurrently (ThreadPoolExecutor, --workers).
  - Two SEPARATE rules checkouts (rules-old, rules-new) instead of one
    checkout switched by git between engines (that only works serially).
  - Repeats default to 1. Repeat 1 alone is sufficient for verification:
    compare.py checks your repeat-1 finding/error sets against the
    published bundle artifacts. Use --repeats 2 to also reproduce the
    original repeatability check (rep1 == rep2).
  - Checkpointed per (engine, batch, repeat) via batch-records.jsonl;
    re-runs skip completed invocations and resume the rest.

Paths are arguments so the same script runs inside the Docker image
(defaults: /work, /opt/venvs, /bundle) and on a host for testing.
The freeze directory MUST be named "freeze": raw output paths are
relativized by splitting on "/freeze/" when comparing against the
published bundle artifacts.

Usage:
  python3 run_parallel.py --root /work --tools /opt/venvs \
      --rules-old /work/freeze/rules-old --rules-new /work/freeze/rules-new \
      [--repeats 1|2] [--jobs N] [--workers N] [--batches a,b] [--dry-run]
"""
import argparse, hashlib, json, os, subprocess, sys, threading, time
from concurrent.futures import ThreadPoolExecutor

def sha(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()

def build_batches(fz, man):
    batches = {}
    def resolve(tr, fid):
        if tr == "java":
            return os.path.join(fz, "owasp-full/src/main/java/org/owasp/benchmark/testcode", fid + ".java")
        if tr == "c":
            return os.path.join(fz, "juliet-full/testcases", fid)
        if tr == "project-java":
            return os.path.join(fz, "pc-java", fid)
        if tr == "project-c":
            return os.path.join(fz, "pc-c", fid)
        raise AssertionError(tr)
    def add(key, tr, fid):
        batches.setdefault(key, {"track": tr, "files": []})["files"].append((fid, resolve(tr, fid)))
    for it in man["items"]:
        tr = it["track"]
        if tr == "java":
            add("sg-java-corpus", tr, it["id"])
        elif tr == "project-java":
            add("sg-java-project", tr, it["id"])
        elif tr == "c":
            add(f"sg-c-{it['cwe']}", tr, it["id"])
        elif tr == "project-c":
            add("sg-c-project", tr, it["id"])
    for key in list(batches):
        if key.startswith("sg-c-"):
            batches["ff-" + key[3:]] = dict(batches[key])
    return batches

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", default="/work")
    ap.add_argument("--tools", default="/opt/venvs")
    ap.add_argument("--rules-old", default=None)
    ap.add_argument("--rules-new", default=None)
    ap.add_argument("--repeats", type=int, choices=(1, 2), default=1)
    ap.add_argument("--jobs", type=int, default=os.cpu_count() or 1)
    ap.add_argument("--workers", type=int, default=min(4, os.cpu_count() or 1))
    ap.add_argument("--batches", default=None, help="comma list; default all")
    ap.add_argument("--dry-run", action="store_true")
    a = ap.parse_args()
    fz = os.path.join(a.root, "freeze")
    out = os.path.join(a.root, "outputs")
    os.makedirs(out, exist_ok=True)
    rules_old = a.rules_old or os.path.join(fz, "rules-old")
    rules_new = a.rules_new or os.path.join(fz, "rules-new")
    man = json.load(open(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                      "..", "manifests", "freeze-corpus-manifest.json"))) \
        if os.path.exists(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                       "..", "manifests", "freeze-corpus-manifest.json")) \
        else json.load(open(os.path.join(a.root, "manifests", "freeze-corpus-manifest.json")))
    batches = build_batches(fz, man)
    if a.batches:
        want = set(a.batches.split(","))
        batches = {k: v for k, v in batches.items() if k in want}
        assert len(batches) == len(want), f"unknown batch in {want}"
    print(f"batches: {len(batches)}")
    for k in sorted(batches):
        print(f"  {k}: {len(batches[k]['files'])} files")
    if a.dry_run:
        print("DRY RUN: no scans.")
        return
    # SHA-verify the entire frozen corpus before scanning anything.
    mansha = {i["id"]: i["sha256"] for i in man["items"]}
    seen, n = set(), 0
    for b in batches.values():
        for fid, p in b["files"]:
            if fid in seen:
                continue
            seen.add(fid)
            assert os.path.isfile(p), f"missing file: {p}"
            assert sha(p) == mansha[fid], f"SHA mismatch: {fid}"
            n += 1
    print(f"SHA-verified {n} unique frozen files", flush=True)
    rec_path = os.path.join(a.root, "batch-records.jsonl")
    done = set()
    if os.path.exists(rec_path):
        for line in open(rec_path):
            try:
                r = json.loads(line)
            except Exception:
                continue
            if r.get("exit_code") == 0 and os.path.exists(os.path.join(out, r["stdout_file"])):
                done.add((r["engine"], r["batch"], r["repeat"]))
    print(f"resuming: {len(done)} invocations already complete", flush=True)
    lock = threading.Lock()
    recf = open(rec_path, "a")
    def record(rec):
        with lock:
            recf.write(json.dumps(rec) + "\n")
            recf.flush()
        print(f"  {rec['engine']} {rec['batch']} rep{rec['repeat']} exit={rec['exit_code']} "
              f"{rec['wall_s']}s results={rec.get('n_results')} errors={rec.get('n_errors')}", flush=True)
    env = dict(os.environ, SEMGREP_ENABLE_VERSION_CHECK="0")
    sg = [("semgrep-1.172.0", os.path.join(a.tools, "venv-old/bin/semgrep"), rules_old,
           "f2b6518560d23c4fcf9a97dd41cbdbbe6be49de7"),
          ("semgrep-1.182.0", os.path.join(a.tools, "venv-new/bin/semgrep"), rules_new,
           "17e31e11ebac99fb7dfe1cd288f7a32151b6f3f9")]
    ff = [("flawfinder-2.0.19", os.path.join(a.tools, "venv-old/bin/flawfinder")),
          ("flawfinder-2.0.20", os.path.join(a.tools, "venv-new/bin/flawfinder"))]
    tasks = []
    def sg_task(name, binary, rules, commit, batch, rep):
        if (name, batch, rep) in done:
            print(f"  skip (done): {name} {batch} rep{rep}", flush=True)
            return
        lang = "java" if "-java-" in batch else "c"
        paths = [p for _, p in batches[batch]["files"]]
        key = f"{name}_{batch}_r{rep}"
        outp = os.path.join(out, key + ".json")
        t0 = time.time()
        try:
            r = subprocess.run([binary, "--config", os.path.join(rules, lang),
                                "--json", "--jobs", str(a.jobs)] + paths,
                               capture_output=True, text=True, timeout=3600, env=env)
            code, so, se = r.returncode, r.stdout, r.stderr
        except subprocess.TimeoutExpired:
            code, so, se = "TIMEOUT", "", "timeout after 3600s"
        wall = round(time.time() - t0, 2)
        open(outp, "w").write(so)
        rec = {"engine": name, "batch": batch, "lang": lang, "repeat": rep,
               "exit_code": code, "wall_s": wall, "n_files": len(paths),
               "stdout_file": os.path.basename(outp),
               "stderr_head": se[:2000], "pack_commit": commit}
        try:
            d = json.loads(so) if so.strip() else None
            if d is not None:
                rec["n_results"] = len(d.get("results", []))
                rec["n_errors"] = len(d.get("errors", []))
                rec["error_files"] = sorted({e.get("path", "") for e in d.get("errors", [])})[:20]
                rec["skipped_rules"] = d.get("skipped_rules", "ABSENT")
            else:
                rec["n_results"] = None; rec["n_errors"] = None; rec["parse_note"] = "empty stdout"
        except Exception as e:
            rec["n_results"] = None; rec["n_errors"] = None; rec["parse_note"] = f"unparseable: {e}"
        record(rec)
    def ff_task(name, binary, batch, rep):
        if (name, batch, rep) in done:
            print(f"  skip (done): {name} {batch} rep{rep}", flush=True)
            return
        paths = [p for _, p in batches[batch]["files"]]
        key = f"{name}_{batch}_r{rep}"
        outp = os.path.join(out, key + ".csv")
        t0 = time.time()
        try:
            r = subprocess.run([binary, "--csv"] + paths,
                               capture_output=True, text=True, timeout=3600)
            code, so, se = r.returncode, r.stdout, r.stderr
        except subprocess.TimeoutExpired:
            code, so, se = "TIMEOUT", "", "timeout after 3600s"
        wall = round(time.time() - t0, 2)
        open(outp, "w").write(so)
        lines = [l for l in so.splitlines() if l.strip() and not l.startswith("File,")]
        record({"engine": name, "batch": batch, "lang": "c", "repeat": rep,
                "exit_code": code, "wall_s": wall, "n_files": len(paths),
                "stdout_file": os.path.basename(outp),
                "stderr_head": se[:2000], "n_results": len(lines), "n_errors": None})
    for name, binary, rules, commit in sg:
        for batch in sorted(batches):
            if not batch.startswith("sg-"):
                continue
            for rep in range(1, a.repeats + 1):
                tasks.append((sg_task, (name, binary, rules, commit, batch, rep)))
    for name, binary in ff:
        for batch in sorted(batches):
            if not batch.startswith("ff-"):
                continue
            for rep in range(1, a.repeats + 1):
                tasks.append((ff_task, (name, binary, batch, rep)))
    print(f"invocations to run: {len(tasks)} (workers={a.workers}, jobs={a.jobs})", flush=True)
    with ThreadPoolExecutor(max_workers=a.workers) as ex:
        list(ex.map(lambda t: t[0](*t[1]), tasks))
    recf.close()
    print("SCAN COMPLETE", flush=True)

if __name__ == "__main__":
    main()
