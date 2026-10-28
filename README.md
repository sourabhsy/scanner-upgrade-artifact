# Artifact for “When Your Security Scanner Changes: A Practical Upgrade-Validation Workflow”

Evidence and local-verification package for the bounded IEEE Software
case study: two scanner upgrades (Semgrep 1.172.0 → 1.182.0,
Flawfinder 2.0.19 → 2.0.20) evaluated on a frozen corpus of 23,818
files, six cases (each tool on each benchmark track and each project).
The workflow recommends PROCEED in all six cases; the reference
decision under pre-set criteria is ADOPT in all six.

## Layout

- `evidence/` — the full-run evidence bundle: reports, tables, sealed
  baselines, block decisions, observations, batch records, and the
  scoring/analysis/replay scripts. See `evidence/README.md` for the
  table-to-artifact links and file hashes. (The manuscript itself is
  the submission and is not included here.)
- `local-verification/` — independent local reproduction of the
  archived repeat-1 results (v1, 2026-10-27): comparison report,
  output hashes, environment details, and the wheels manifest.
- `verifier/` — the Docker verifier's Dockerfile, scripts, and README.
  Build and run it to repeat the scans and comparison locally.
- `corpus/` — corpus sources, pins, and fetch steps. The corpus files
  themselves are not stored here (702 MB of third-party sources).

## How to verify

- Evidence replay: follow the replay instructions in
  `evidence/README.md` (`replay.py` re-derives the tables from the
  bundled findings and coverage records).
- Docker verifier (from the unzipped verifier folder, or from
  `verifier/` here):
  `docker build -t t5-verify .` then
  `docker run --rm -v "$PWD/t5-verify-work:/work" t5-verify`
  (add `--skip-setup` to reuse checkouts and environments; it skips
  setup only, not scanning).
- Comparison only, no scans (against existing outputs):
  `docker run --rm --entrypoint python3 -v "$PWD/t5-verify-work:/work" t5-verify /app/scripts/compare.py --outputs /work/outputs --bundle /bundle`
  or standalone:
  `python3 verifier/scripts/compare.py --outputs <outputs-dir> --bundle evidence`

## Provenance and limits

- `evidence/` is the PR #48 bundle at head `231a8841`, minus the
  manuscript copy, with an adapted README (title, companion line, and
  the dropped manuscript hash line are the only changes).
- `local-verification/` is v1 (2026-10-27, author-run): 28/28 rep1
  outputs reproduced, compare verdict ALL COMPARE CHECKS PASS.
  Repeat 2 remains unverified; see its README for the stated limits.
- The prebuilt 158 MB verifier zip is not stored in git (over GitHub's
  100 MB blob limit). Its SHA-256 is
  `77c4031e92f893188a2e688a50a384b18fbc5510c0eca05ce9dacb95f36624ae`;
  it accompanies the submission as supplemental material, and the
  wheels manifest in `local-verification/` lets anyone rebuild an
  equivalent offline package from PyPI.

## License

MIT — see `LICENSE`.
