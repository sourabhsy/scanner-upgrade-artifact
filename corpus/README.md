# Corpus sources (frozen corpus, 23,818 files)

The corpus files themselves are NOT stored in this repo (702 MB of
third-party sources). Everything below is pinned so the exact corpus
can be refetched. Pins are as recorded in the study's Phase-1 freeze
record (2026-10-26).

## Sources and pins

| Track | Source | Pin | Files selected |
|---|---|---|---|
| Java | OWASP-Benchmark/BenchmarkJava | `acc50f20` | 2,740 `BenchmarkTest*.java` (1,415 vulnerable / 1,325 not) |
| C | arichardson/juliet-test-suite-c | `f88433e` | 20,574 `.c` files in 5 CWE dirs (CWE121: 5,906; CWE78: 5,600; CWE190: 5,040; CWE122: 3,656; CWE476: 372) |
| Project Java | apache/commons-lang | `a8e08aef` | 264 `src/main/java/**/*.java` |
| Project C | curl/curl | `19b29900` | 240 `lib/**/*.c` + `src/**/*.c` |

Fetch any source with:

```
git clone https://github.com/<source>.git
git checkout <pin>
```

## Exclusions (stated, not silent)

- Juliet `.cpp` files (11,701) are OUT of the C track (`.c` only).
- Split testcases — where the bad function calls a sink in another
  file, so no single region contains the weakness — are excluded from
  Layer B (verified-effectiveness scoring) entirely: 10,856 files.
- The two project cases were admitted under the freeze record's
  written exception; no merge-enforcement claim is made for them.

## Tool and rule pins

- Semgrep 1.172.0 → 1.182.0. Rule-pack snapshots `f2b65185` /
  `17e31e11` are byte-identical on all 142 hashed files, so the
  Semgrep transition is engine-only drift.
- Flawfinder 2.0.19 → 2.0.20 (security-fix release).
