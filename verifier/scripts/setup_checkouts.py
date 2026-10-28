#!/usr/bin/env python3
"""Clone (or verify) the frozen T5 checkouts into <root>/freeze.

All sources are public GitHub repos. Clones use --filter=blob:none
(partial clone: commit/tree history plus only the blobs the sparse
checkout needs) and cone-mode sparse checkout, so the download is
close to the working-tree size, not full repo history.

Idempotent: an existing checkout whose HEAD already equals the pinned
SHA is left alone; a checkout at another SHA is moved to the pinned
SHA (full clones contain it). A missing checkout is cloned fresh.
After checkout, rules files are verified against the frozen pack
manifest (142 files per engine) and every checkout's HEAD is asserted.

Layout under <root>/freeze (the name "freeze" is required: raw output
paths are relativized by splitting on "/freeze/"):
  owasp-full, juliet-full, pc-java, pc-c, rules-old, rules-new
"""
import json, os, subprocess, sys

CHECKOUTS = [
    ("owasp-full", "https://github.com/OWASP-Benchmark/BenchmarkJava.git",
     "acc50f20ec449e2b977a7c409fa8175491657cba",
     ["src/main/java/org/owasp/benchmark/testcode"]),
    ("juliet-full", "https://github.com/arichardson/juliet-test-suite-c.git",
     "f88433e3443648a17671398797a04ea1f8e1a274",
     ["testcases/CWE121_Stack_Based_Buffer_Overflow",
      "testcases/CWE122_Heap_Based_Buffer_Overflow",
      "testcases/CWE190_Integer_Overflow",
      "testcases/CWE476_NULL_Pointer_Dereference",
      "testcases/CWE78_OS_Command_Injection"]),
    ("pc-java", "https://github.com/apache/commons-lang.git",
     "a8e08aef142048a88be63d3a60848f822af406fd",
     ["src/main/java"]),
    ("pc-c", "https://github.com/curl/curl.git",
     "19b299005fbe2d895f4ad525cfdae62a2220c3ea",
     ["lib", "src"]),
    ("rules-old", "https://github.com/semgrep/semgrep-rules.git",
     "f2b6518560d23c4fcf9a97dd41cbdbbe6be49de7",
     ["java", "c"]),
    ("rules-new", "https://github.com/semgrep/semgrep-rules.git",
     "17e31e11ebac99fb7dfe1cd288f7a32151b6f3f9",
     ["java", "c"]),
]

def run(cmd, cwd=None):
    print("  $ " + " ".join(cmd), flush=True)
    subprocess.run(cmd, cwd=cwd, check=True)

def head(dest):
    return subprocess.run(["git", "-C", dest, "rev-parse", "HEAD"],
                          capture_output=True, text=True, check=True).stdout.strip()

def sha256_file(p):
    import hashlib
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()

def main():
    root = sys.argv[1] if len(sys.argv) > 1 else "/work"
    here = os.path.dirname(os.path.abspath(__file__))
    pack = None
    for cand in (os.path.join(here, "..", "manifests", "freeze-pack-manifest.json"),
                 os.path.join(root, "manifests", "freeze-pack-manifest.json")):
        if os.path.exists(cand):
            pack = json.load(open(cand))
            break
    fz = os.path.join(root, "freeze")
    os.makedirs(fz, exist_ok=True)
    for name, url, sha, dirs in CHECKOUTS:
        dest = os.path.join(fz, name)
        if os.path.isdir(os.path.join(dest, ".git")):
            if head(dest) == sha:
                print(f"{name}: already at {sha[:8]}", flush=True)
                continue
            print(f"{name}: moving to {sha[:8]}", flush=True)
            run(["git", "-C", dest, "checkout", sha])
        else:
            print(f"{name}: cloning {url} @ {sha[:8]}", flush=True)
            run(["git", "clone", "--filter=blob:none", "--no-checkout", url, dest])
            run(["git", "-C", dest, "sparse-checkout", "init", "--cone"])
            run(["git", "-C", dest, "sparse-checkout", "set"] + dirs)
            run(["git", "-C", dest, "checkout", sha])
        assert head(dest) == sha, f"{name}: HEAD {head(dest)} != {sha}"
        print(f"{name}: HEAD verified {sha}", flush=True)
    if pack:
        for rules, key in (("rules-old", "semgrep-1.172.0"), ("rules-new", "semgrep-1.182.0")):
            n = 0
            for entry in pack[key]["files"]:
                p = os.path.join(fz, rules, entry["file"])
                assert os.path.isfile(p), f"missing rule file: {p}"
                assert sha256_file(p) == entry["sha256"], f"rule SHA mismatch: {p}"
                n += 1
            print(f"{rules}: {n} rule files verified against pack manifest", flush=True)
    print("CHECKOUTS READY", flush=True)

if __name__ == "__main__":
    main()
