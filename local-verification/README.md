# Local verification artifact (t5-local-verification-v1, 2026-10-27)

Independent local reproduction of the archived VM repeat-1 results for the
bounded IEEE Software case study (“When Your Security Scanner Changes”), run by the author on a
Windows machine with Docker Desktop using the wheels-bundled Docker
verifier. Published in this repo; completed with the author's comparison
report, output hashes, and environment details (see Contents). The version label is as proposed; rename in a follow-up
if the author prefers a different label.

## Contents

- `README.md` (this file): artifact manifest, verification limits, and
  re-run instructions.
- `wheels-manifest.json`: the 71 Python wheels bundled in the verifier
  (semgrep 1.172.0 + flawfinder 2.0.19 in venv-old; semgrep 1.182.0 +
  flawfinder 2.0.20 in venv-new), each with its SHA-256. All 71 hashes
  were verified against PyPI's published hashes before the verifier
  was delivered.
- `comparison-report.txt`: full `docker logs` output of the author's
  verification run (241 lines; ALL COMPARE CHECKS PASS; 146 PASS lines;
  semgrep/c-project flips (0, 0, 8) reproduced exactly).
- `output-hashes.csv`: SHA-256 of the author's 28 rep1 outputs.
- `environment.txt`: Docker version and image listing from the author's
  machine (Docker Desktop 4.97.0, engine 29.9.2, image
  `t5-verify:latest` a6ea3798e29d, 1.13 GB; digest `<none>` as expected
  for a locally built image; CPU/memory allocation not recorded).

## Verifier package

- File: `t5-verify-docker-wheels.zip` (158 MB), version
  t5-local-verification-v1.
- SHA-256: `77c4031e92f893188a2e688a50a384b18fbc5510c0eca05ce9dacb95f36624ae`
- The zip is NOT stored in this directory or in the repository:
  GitHub rejects blobs over 100 MB, so the 158 MB package cannot be
  pushed to git as a file. It will accompany the submission
  as supplemental material. Anyone holding the zip can verify it
  against the hash above, and the wheels manifest lets anyone
  rebuild an equivalent offline package from PyPI.
- Re-run (from the unzipped verifier folder):
  `docker build -t t5-verify .` then one of:
  - Full run (setup + scans + comparison):
    `docker run --rm -v "$PWD/t5-verify-work:/work" t5-verify`
  - Skip setup only (checkouts and virtual environments are reused;
    scans still run for batches without existing outputs, finished
    batches are checkpoint-skipped; then comparison runs):
    `docker run --rm -v "$PWD/t5-verify-work:/work" t5-verify --skip-setup`
  - Comparison only, no scans (against existing outputs):
    `docker run --rm --entrypoint python3 -v "$PWD/t5-verify-work:/work" t5-verify /app/scripts/compare.py --outputs /work/outputs --bundle /bundle`
  Note: `--skip-setup` skips setup only; it does not skip scanning.

## Verification limits (stated, not implied)

- Local repeat 1 reproduces the archived VM results (28/28 rep1 outputs;
  187,765 findings; compare verdict ALL COMPARE CHECKS PASS, including
  semgrep/c-project flips (0, 0, 8) reproduced exactly).
- Repeat 2 remains unverified, so this supports repeat-1 reproduction
  only, not full repeatability or overall publication readiness.
- The historical baseline-sealing order remains independently unverified.
- A second local run would strengthen repeatability evidence but is not
  needed to establish the repeat-1 match.
- The author's extended-comparison summary (28 outputs, 187,765 findings,
  215 extended checks) is the author's own report; its 215-check
  composition has not been reconciled against compare.py's 146 PASS
  lines and is not repeated here as a verified count.
