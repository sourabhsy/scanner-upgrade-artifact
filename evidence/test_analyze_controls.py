#!/usr/bin/env python3
"""Control tests for analyze.py's derive_workflow / derive_reference.

Reproduces the reviewer's three isolated controls plus the supported
cases, against the ACTUAL function definitions extracted from
analyze.py (not copies). Fails loudly on any mismatch.
"""
import ast, sys
from pathlib import Path

# Load the SIBLING analyzer from this bundle, not a hardcoded
# author-machine path (review round 3: the old absolute path raised
# FileNotFoundError before any control ran outside the workspace).
src = Path(__file__).with_name("analyze.py").read_text()
tree = ast.parse(src)
want = {"derive_workflow", "derive_reference", "UnsupportedCase"}
nodes = [n for n in tree.body
         if isinstance(n, (ast.FunctionDef, ast.ClassDef)) and n.name in want]
assert {n.name for n in nodes} == want, "could not extract functions"
ns = {}
exec(compile(ast.Module(body=nodes, type_ignores=[]), "analyze_funcs", "exec"), ns)
derive_workflow = ns["derive_workflow"]
derive_reference = ns["derive_reference"]
UnsupportedCase = ns["UnsupportedCase"]

fails = []
def check(name, got, want_):
    ok = got == want_
    print(("PASS " if ok else "FAIL ") + name + f" -> {got}")
    if not ok:
        fails.append(name)

# Control (a): new parse failure (coverage loss) -> HOLD / HOLD (was ADOPT)
check("new-parse-failure workflow",
      derive_workflow(False, 1, set(), 0), "HOLD")
check("new-parse-failure reference",
      derive_reference(False, 1, set(), 0), ("HOLD", "MECHANICAL"))
# Control (b): newly skipped rule -> HOLD / HOLD (was PROCEED/ADOPT)
check("newly-skipped-rule workflow",
      derive_workflow(False, 0, {"some-rule"}, 0), "HOLD")
check("newly-skipped-rule reference",
      derive_reference(False, 0, {"some-rule"}, 0), ("HOLD", "MECHANICAL"))
# Control (c): disappeared file (coverage loss) -> HOLD / HOLD (was PROCEED)
check("disappeared-file workflow",
      derive_workflow(False, 1, set(), 0), "HOLD")
# Invocation failure -> HOLD / HOLD
check("invocation-failure workflow",
      derive_workflow(True, 0, set(), 0), "HOLD")
check("invocation-failure reference",
      derive_reference(True, 0, set(), 0), ("HOLD", "MECHANICAL"))
# Zero-driver -> PROCEED / ADOPT-BEHAVIORAL
check("zero-driver workflow",
      derive_workflow(False, 0, set(), 0), "PROCEED")
check("zero-driver reference",
      derive_reference(False, 0, set(), 0), ("ADOPT", "BEHAVIORAL"))
# Block flips: workflow CHECKs; reference REFUSES (unsupported scope)
check("flips workflow",
      derive_workflow(False, 0, set(), 3), "CHECK")
try:
    derive_reference(False, 0, set(), 3)
    print("FAIL flips reference did not raise")
    fails.append("flips reference")
except UnsupportedCase as e:
    print("PASS flips reference raises UnsupportedCase:", e)
except Exception as e:  # noqa
    print("FAIL flips reference wrong exception:", type(e), e)
    fails.append("flips reference")

if fails:
    print("FAILURES:", fails)
    sys.exit(1)
print("ALL CONTROLS PASS")
