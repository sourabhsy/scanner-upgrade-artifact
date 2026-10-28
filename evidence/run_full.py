#!/usr/bin/env python3
"""T5 full experiment — SCAN PHASE (authorized 2026-10-26; CPU-only, local).

Frozen engines/packs/corpus, batched per directory, 2 repeats, strictly
serial, checkpointed per batch. Resume-safe: batches already recorded
with exit 0 and an existing output file are skipped.

Batches (from freeze-corpus-manifest.json, exact frozen sets):
  semgrep java corpus (2,740), java project (264),
  semgrep C per CWE dir (121/78/190/122/476), C project (240),
  flawfinder C per CWE dir + C project.
Engines: semgrep 1.172.0 (pack f2b65185) + 1.182.0 (pack 17e31e11),
flawfinder 2.0.19 + 2.0.20. No scans of anything outside the frozen
manifest. No GitHub writes. No scoring here — scoring/analysis run
after scanning, against these raw outputs.

Outputs: fullrun/outputs/<engine>_<batch>_r<rep>.json|.csv +
fullrun/batch-records.jsonl (one record per invocation, flushed).
Usage: --dry-run lists batches and counts without scanning.
"""
import hashlib, json, os, subprocess, sys, time

FZ = os.path.expanduser("~/workspace/research/t5/freeze")
FR = os.path.expanduser("~/workspace/research/t5/fullrun")
OUT = os.path.join(FR, "outputs")
os.makedirs(OUT, exist_ok=True)
VENV = os.path.expanduser("~/workspace/research/venv")

def sha(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()

def resolve(tr, fid):
    if tr == "java":
        return os.path.join(FZ, "owasp-full/src/main/java/org/owasp/benchmark/testcode", fid + ".java")
    if tr == "c":
        return os.path.join(FZ, "juliet-full/testcases", fid)
    if tr == "project-java":
        return os.path.join(FZ, "pc-java", fid)
    if tr == "project-c":
        return os.path.join(FZ, "pc-c", fid)
    raise AssertionError(tr)

def build_batches():
    man = json.load(open(os.path.join(FZ, "freeze-corpus-manifest.json")))
    batches = {}
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
    # flawfinder batches mirror the C batches (C corpus per CWE + project)
    for key in list(batches):
        if key.startswith("sg-c-"):
            batches["ff-" + key[3:]] = dict(batches[key])
    return batches

def main():
    dry = "--dry-run" in sys.argv
    batches = build_batches()
    print(f"batches: {len(batches)}")
    for k in sorted(batches):
        print(f"  {k}: {len(batches[k]['files'])} files")
    if dry:
        print("DRY RUN: no scans.")
        return
    # SHA-verify the entire frozen corpus before scanning anything.
    n = 0
    man = {i["id"]: i["sha256"] for i in json.load(open(os.path.join(FZ, "freeze-corpus-manifest.json")))["items"]}
    seen = set()
    for b in batches.values():
        for fid, p in b["files"]:
            if fid in seen:
                continue
            seen.add(fid)
            assert os.path.isfile(p), p
            assert sha(p) == man[fid], fid
            n += 1
    print(f"SHA-verified {n} unique frozen files", flush=True)
    # Resume state: (engine, batch, repeat) already complete.
    rec_path = os.path.join(FR, "batch-records.jsonl")
    done = set()
    if os.path.exists(rec_path):
        for line in open(rec_path):
            try:
                r = json.loads(line)
            except Exception:
                continue
            if r.get("exit_code") == 0 and os.path.exists(os.path.join(OUT, r["stdout_file"])):
                done.add((r["engine"], r["batch"], r["repeat"]))
    print(f"resuming: {len(done)} batches already complete", flush=True)
    recf = open(rec_path, "a")
    def record(rec):
        recf.write(json.dumps(rec) + "\n")
        recf.flush()
        print(f"  {rec['engine']} {rec['batch']} rep{rec['repeat']} exit={rec['exit_code']} "
              f"{rec['wall_s']}s results={rec.get('n_results')} errors={rec.get('n_errors')}", flush=True)
    env = dict(os.environ, SEMGREP_ENABLE_VERSION_CHECK="0")
    sg = [("semgrep-1.172.0", os.path.join(FZ, "venv-freeze/bin/semgrep"), "f2b6518560d23c4fcf9a97dd41cbdbbe6be49de7"),
          ("semgrep-1.182.0", os.path.join(VENV, "bin/semgrep"), "17e31e11ebac99fb7dfe1cd288f7a32151b6f3f9")]
    for name, binary, commit in sg:
        subprocess.run(["git", "checkout", commit], cwd=os.path.join(FZ, "rules-full"),
                       check=True, capture_output=True)
        for batch in sorted(batches):
            if not batch.startswith("sg-"):
                continue
            lang = "java" if "-java-" in batch else "c"
            paths = [p for _, p in batches[batch]["files"]]
            for rep in (1, 2):
                if (name, batch, rep) in done:
                    print(f"  skip (done): {name} {batch} rep{rep}", flush=True)
                    continue
                key = f"{name}_{batch}_r{rep}"
                outp = os.path.join(OUT, key + ".json")
                t0 = time.time()
                try:
                    r = subprocess.run([binary, "--config", os.path.join(FZ, "rules-full", lang),
                                        "--json", "--jobs", "1"] + paths,
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
    ff = [("flawfinder-2.0.19", os.path.join(FZ, "venv-freeze/bin/flawfinder")),
          ("flawfinder-2.0.20", os.path.join(VENV, "bin/flawfinder"))]
    for name, binary in ff:
        for batch in sorted(batches):
            if not batch.startswith("ff-"):
                continue
            paths = [p for _, p in batches[batch]["files"]]
            for rep in (1, 2):
                if (name, batch, rep) in done:
                    print(f"  skip (done): {name} {batch} rep{rep}", flush=True)
                    continue
                key = f"{name}_{batch}_r{rep}"
                outp = os.path.join(OUT, key + ".csv")
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
    recf.close()
    print("FULL SCAN COMPLETE", flush=True)

if __name__ == "__main__":
    main()
