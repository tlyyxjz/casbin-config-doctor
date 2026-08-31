# Casbin Config Doctor

Diagnose, generate, and fix [Casbin](https://github.com/casbin/casbin) `model.conf` / `policy.csv` configurations — and get a plain-language explanation of **why `enforce()` returns false**.

Published on the RailCall marketplace: **https://railcall.ai/marketplace/tlyyxjz/casbin-config-doctor**

[![tests](https://img.shields.io/badge/tests-26%20passed-brightgreen)]() [![python](https://img.shields.io/badge/python-3.8%2B-blue)]() [![deps](https://img.shields.io/badge/dependencies-stdlib%20only-orange)]()

## Why

Every Casbin user eventually hits the same wall: `enforce()` returns `false`, and nothing tells you *which* part of the matcher failed, *which* policy line almost matched, or whether the model file is even structurally valid. Casbin Config Doctor answers those questions in one command.

## Commands (8)

| Command | What it does |
|---|---|
| `diagnose` | Full check-up: model syntax + token counts + duplicates + role cycles, with severity-rated issue list |
| `validate_model` | Validate `model.conf`: required sections, empty sections, matcher↔definition variable cross-check |
| `explain_deny` | Step-by-step explanation of a denied request: roles considered, matching rules, **near-miss rules with the exact failing field** |
| `generate` | Plain-language requirement → `model.conf` + `policy.csv` (RBAC / RESTful / ABAC templates) |
| `check_policy` | Validate one policy line's token count against the model's `policy_definition` |
| `detect_duplicates` | Find duplicate policy rules (with first-seen line numbers) |
| `detect_role_cycle` | Detect inheritance cycles in `g` rules via DFS |
| `compare` | Diff two policy files: added / removed / unchanged |

## Quick start

```bash
railcall market install tlyyxjz/casbin-config-doctor
# then in RailCall Studio: reload modules and try e.g.
#   explain_deny { model_conf: "...", policy_csv: "...", sub: "alice", obj: "data1", act: "write" }
```

## Example: explaining a denial

```json
{
  "model_conf": "[request_definition]\nr = sub, obj, act\n...",
  "policy_csv": "p, admin, data1, read\ng, alice, admin",
  "sub": "alice", "obj": "data2", "act": "write"
}
```

→ verdict `allowed: false`, roles expanded to `["admin"]`, plus near-miss rules:

```json
{ "line": 1, "rule": "p,admin,data1,read",
  "why_not": ["object mismatch: policy has 'data1', request is 'data2'"] }
```

## Correctness

`explain_deny` verdicts are **cross-validated against the real `casbin` library**: on the official `casbin/casbin` example configs, the doctor's allow/deny verdict matches `casbin.Enforcer.enforce()` 5/5 (see `tests/test_cross_validation_casbin.py`, auto-skipped when casbin isn't installed — the module itself is stdlib-only).

## Tests

26 tests, all green:

```bash
python -m pytest tests/ -q
# ............                                                            [100%] 26 passed
```

- 13 unit tests (happy path + edge cases: wrong token counts, cycles, duplicates, unknown templates)
- 8 smoke tests against **real Casbin example configs** from `casbin/casbin/examples` (rbac, domains, keymatch, abac, basic)
- 5 cross-validation tests against the actual `casbin` library

## Design notes

- **Stdlib only** — installs and runs anywhere Python 3 runs; no supply-chain surface
- **Zero side effects** — every command is read-only; configs are passed as strings
- **Evidence over guessing** — denials come with near-miss rules and the specific failing field, not just "false"
- Signed and published on the RailCall marketplace; signature verified at install time

## License

MIT © 2026 tlyyxjz
