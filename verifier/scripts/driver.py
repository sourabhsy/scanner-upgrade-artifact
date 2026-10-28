#!/usr/bin/env python3
"""Driver: setup checkouts -> scan -> compare, inside the container.

Defaults assume the Docker layout (workdir /work, venvs /opt/venvs,
bundle /bundle, scripts /app/scripts). Every path is overridable for
host-side testing.

Steps:
  1. setup_checkouts.py (clone missing checkouts, verify HEAD SHAs and
     rule-file SHAs). Skipped with --skip-setup.
  2. run_parallel.py (SHA-verify corpus, scan, checkpoint per batch).
  3. compare.py (your outputs vs the published bundle artifacts).
Exits non-zero if any step fails. Scan outputs live in <root>/outputs
and persist via the Docker volume mount; the container itself is
disposable (--rm is safe).
"""
import argparse, os, subprocess, sys

HERE = os.path.dirname(os.path.abspath(__file__))

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", default="/work")
    ap.add_argument("--tools", default="/opt/venvs")
    ap.add_argument("--bundle", default="/bundle")
    ap.add_argument("--repeats", type=int, choices=(1, 2), default=1)
    ap.add_argument("--jobs", type=int, default=os.cpu_count() or 1)
    ap.add_argument("--workers", type=int, default=min(4, os.cpu_count() or 1))
    ap.add_argument("--batches", default=None)
    ap.add_argument("--skip-setup", action="store_true")
    ap.add_argument("--skip-compare", action="store_true")
    ap.add_argument("--dry-run", action="store_true")
    a = ap.parse_args()
    def run(cmd):
        print("$ " + " ".join(cmd), flush=True)
        subprocess.run(cmd, check=True)
    if not a.skip_setup:
        run([sys.executable, os.path.join(HERE, "setup_checkouts.py"), a.root])
    cmd = [sys.executable, os.path.join(HERE, "run_parallel.py"),
           "--root", a.root, "--tools", a.tools,
           "--rules-old", os.path.join(a.root, "freeze", "rules-old"),
           "--rules-new", os.path.join(a.root, "freeze", "rules-new"),
           "--repeats", str(a.repeats), "--jobs", str(a.jobs),
           "--workers", str(a.workers)]
    if a.batches:
        cmd += ["--batches", a.batches]
    if a.dry_run:
        cmd += ["--dry-run"]
    run(cmd)
    if not a.skip_compare and not a.dry_run:
        try:
            run([sys.executable, os.path.join(HERE, "compare.py"),
                 "--outputs", os.path.join(a.root, "outputs"), "--bundle", a.bundle])
        except subprocess.CalledProcessError:
            print("\nCOMPARE FAILED — see the FAIL lines above.", flush=True)
            sys.exit(1)
    print(f"\nDone. Outputs: {os.path.join(a.root, 'outputs')}", flush=True)

if __name__ == "__main__":
    main()
