# T5 local verification — Docker edition (wheels-bundled)

Reproduce the T5 full experiment (PR #48, "When Your Security Scanner
Changes") on your own machine and check your run against the published
evidence bundle. CPU-only. No Azure account, no GPU, no SDK, no Python
or git needed on your machine — everything except Docker itself lives
inside the image.

This is the wheels-bundled variant: the Semgrep/Flawfinder wheels and
all their dependencies ship inside the package, so the build never
contacts PyPI. Use it if the standard build fails at the pip step with
TLS errors against `files.pythonhosted.org` (observed on a network
where `pypi.org` itself worked fine). Every bundled wheel was verified
against the SHA-256 PyPI publishes for that exact file.

## You need

- **Docker Desktop** (Mac or Windows) — the only install. Get it from
  docker.com. No Python, no git, no SDK, no compiler on the host.

## Steps

1. Unzip this folder. Open a terminal **in the folder** (it contains
   the `Dockerfile`).
2. Build the image (needs internet only for the base image pull from
   Docker Hub; the tool installs are offline from the bundled wheels):
   ```
   docker build -t t5-verify .
   ```
   The `.` matters: it means "this folder". Use NO `--build-arg`
   proxy flags — nothing in this build needs a proxy, and a bogus
   proxy value breaks the apt step.
3. Run it, mounting a folder for the work and outputs:
   ```
   docker run --rm -v "$PWD/t5-verify-work:/work" t5-verify
   ```
   On Windows PowerShell use `-v ${PWD}/t5-verify-work:/work` instead
   of the `$PWD` form.
   - First run clones the frozen corpus/rule snapshots into
     `t5-verify-work/freeze` (needs github.com reachable; skipped on
     later runs), SHA-verifies all 23,818 files, scans, then compares.
   - Later runs reuse the checkouts and skip finished batches
     (checkpointed per batch in `batch-records.jsonl`).
   - `--rm` removes the container when it finishes; your outputs stay,
     because they were in the mounted folder all along.

## What you get

- `t5-verify-work/outputs/` — the 28 repeat-1 scan outputs
  (16 Semgrep JSON + 12 Flawfinder CSV) plus `batch-records.jsonl`.
- Terminal output ending in **ALL COMPARE CHECKS PASS** (or a FAIL
  list with details, and a non-zero exit code, if anything differs).
  If you ran only a subset with `--batches`, the verdict reads
  **PARTIAL RUN** instead: every check for the batches present passed,
  and the skipped checks are listed.
  The compare checks your finding sets, error sets, skipped rules,
  and block lists against the published bundle, plus eligible/raw
  flips per case. If those match, every downstream number matches,
  because scoring and analysis are deterministic functions of exactly
  those inputs.

## Options (append after the image name)

- `--repeats 2` — also run repeat 2 and check rep1 == rep2
  (default 1; repeat 1 alone is sufficient for verification).
- `--jobs N` — Semgrep jobs per invocation (default: container CPUs).
- `--workers N` — concurrent invocations (default: min(4, CPUs)).
- `--batches sg-java-project,ff-c-CWE476` — smoke-test subset.
- `--dry-run` — list batches and counts without scanning.
- `--skip-setup` / `--skip-compare` — skip the checkout / compare step.

Example (full both-repeats run, 8 jobs, 4 workers):

```
docker run --rm -v "$PWD/t5-verify-work:/work" t5-verify --repeats 2 --jobs 8 --workers 4
```

## Timing (estimates, not guarantees)

On the original 2-core VM with Semgrep pinned to one job and batches
serial, the full 56-invocation run took ~9.7 hours (repeat 1 alone:
~4.9 hours). With jobs enabled and batches parallel on a multi-core
machine, repeat 1 lands around 1–2 hours on 8 cores and under an hour
on 16 cores. If Docker Desktop feels slow, check Settings →
Resources → CPUs (give it more cores).

## Troubleshooting (this variant)

- **Build fails pulling the base image.** The only network the build
  needs is Docker Hub (`python:3.12-slim-bookworm`). If that fails,
  it's Docker Hub reachability or Docker Desktop's proxy settings
  (which do cover image pulls). The tool installs cannot fail on TLS:
  they are offline from the bundled wheels.
- **Build fails at the pip step with "no matching distribution".**
  That means a wheel is missing from `wheels/` — a packaging bug on
  the author's side, not your network. Paste the error back.
- **Run fails cloning a snapshot.** The run step needs `github.com`
  reachable from the container. Test with
  `docker run --rm python:3.12-slim-bookworm python -c "import urllib.request; print(urllib.request.urlopen('https://github.com', timeout=15).status)"`.
  If your network needs a proxy for that, pass it at run time
  (unlike build args, `-e` works here because git reads proxy env):
  `docker run -e https_proxy=http://YOUR-PROXY:PORT ...`.
- **`--build-arg` flags are ignored by this Dockerfile.** It declares
  no proxy args (nothing in the build needs them). Passing them only
  produces a "not consumed" warning. Build plain.

## Notes and honest caveats

- Running Semgrep with `--jobs` above 1 can change the *ordering* of
  findings inside the raw JSON files, so your raw outputs may not be
  byte-identical to the originals. That does not matter: every check
  here compares finding *sets*, and all downstream numbers are
  order-independent.
- The scripts inside this image were tested on Linux (parallel runner
  smoke batches + compare against the published bundle: all pass).
  The `docker build` has since been run successfully by the author
  (2026-10-27, Docker Desktop 4.97.0): 28/28 rep1 outputs, compare
  verdict ALL COMPARE CHECKS PASS.
- The evidence bundle baked into the image (`/bundle`) is the bundle
  as packaged with the zip; the `evidence/` folder in this repo carries
  the same measurement data (see its README for current file hashes). The corpus/rule snapshots
  are public GitHub repos cloned at frozen SHAs; the bundle's
  manifests pin every file SHA, and the runner verifies them before
  scanning anything.
