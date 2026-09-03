# Casbin Config Doctor

Diagnose, generate, and fix [Casbin](https://github.com/casbin/casbin) `model.conf` / `policy.csv` configurations — and get a plain-language explanation of **why `enforce()` returns false**.

[![tests](https://github.com/tlyyxjz/casbin-config-doctor/actions/workflows/tests.yml/badge.svg)](https://github.com/tlyyxjz/casbin-config-doctor/actions/workflows/tests.yml)
[![tests](https://img.shields.io/badge/tests-40%20passed-brightgreen)]()
[![python](https://img.shields.io/badge/python-3.9%2B-blue)]()
[![deps](https://img.shields.io/badge/dependencies-stdlib%20only-orange)]()
[![license](https://img.shields.io/badge/license-MIT-green)]()

## Try it online — no install

**https://tlyyxjz.github.io/casbin-doctor-demo/**

Paste your `model.conf` + `policy.csv`, hit diagnose, get the verdict in seconds. Everything runs in your browser; your configuration is never uploaded anywhere.

## Why

Every Casbin user eventually hits the same wall: `enforce()` returns `false`, and nothing tells you *which* part of the matcher failed, *which* policy line almost matched, or whether the model file is even structurally valid. Casbin Config Doctor answers those questions in one command.

## Install

No dependencies, no build step — clone and run:

```bash
git clone https://github.com/tlyyxjz/casbin-config-doctor.git
cd casbin-config-doctor
python doctor.py --help
```

Requires Python 3.9+. Standard library only.

## Usage

```bash
# full check-up of a configuration
python doctor.py diagnose --model model.conf --policy policy.csv

# why is this request denied?
python doctor.py explain-deny --model model.conf --policy policy.csv \
    --sub alice --obj data2 --act read

# multi-tenant (domains) models take an extra --dom
python doctor.py explain-deny --model model.conf --policy policy.csv \
    --sub alice --obj data2 --act read --dom domain1
```

Add `--json` to any command for machine-readable output.

## Commands (8)

| Command | What it does |
|---|---|
| `diagnose` | Full check-up: model syntax + token counts + duplicates + role cycles, with severity-rated issue list |
| `explain-deny` | Step-by-step explanation of a denied request: roles considered, matching rules, **near-miss rules with the exact failing field** |
| `validate-model` | Check `model.conf` structure: required sections, empty sections, matcher↔definition variable cross-check |
| `check-policy` | Validate one policy line's token count against the model's `policy_definition` |
| `detect-duplicates` | Find duplicate policy rules (with first-seen line numbers) |
| `detect-role-cycle` | Detect inheritance cycles in `g` rules via DFS |
| `generate` | Plain-language requirement → `model.conf` + `policy.csv` (RBAC / RESTful / ABAC templates) |
| `compare` | Diff two policy files: added / removed / unchanged |

## Example: explaining a denial

Given this policy:

```
p, admin, data1, read
p, admin, data2, write
g, alice, admin
```

asking why `alice` cannot `read` `data2`:

```console
$ python doctor.py explain-deny --model model.conf --policy policy.csv \
      --sub alice --obj data2 --act read

verdict: DENIED
request: {"sub": "alice", "obj": "data2", "act": "read"}
roles considered: admin, alice
near misses (closest rules that did not match):
  line 1: p,admin,data1,read
      - obj mismatch: policy has 'data1', request is 'data2'
  line 2: p,admin,data2,write
      - act mismatch: policy has 'write', request is 'read'
matcher: g(r.sub, p.sub) && r.obj == p.obj && r.act == p.act
advice: No policy matched even after expanding roles ['admin']. Either add a p
        rule for one of these subjects, or check the matcher.
```

Note what the doctor does **not** say: it does not report a `sub` mismatch, because `alice` reaches `admin` through the `g` rule — the subject position matched. Only the fields that genuinely failed are listed.

## Multi-tenant (domains) models

`explain-deny` understands `r = sub, dom, obj, act` models. Role inheritance is resolved per-domain (`g, alice, admin, domain1`), so a role granted in one tenant does not leak into another, and a cross-tenant mismatch is reported as `dom mismatch` with both values.

## Use it in CI

Every command exits non-zero when it finds a problem, so `diagnose` can gate a build:

```yaml
- run: python doctor.py diagnose --model model.conf --policy policy.csv
```

Exit codes: `0` clean · `1` issues found (for `diagnose`: errors present) · `2` bad usage or unreadable file.

## Also available on RailCall

Published as a signed module on the RailCall marketplace: https://railcall.ai/marketplace/tlyyxjz/casbin-config-doctor

```bash
railcall market install tlyyxjz/casbin-config-doctor
```

## Correctness

`explain_deny` verdicts are **cross-validated against the real `casbin` library**: on the official `casbin/casbin` example configs, the doctor's allow/deny verdict matches `casbin.Enforcer.enforce()` 5/5 (see `tests/test_cross_validation_casbin.py`, auto-skipped when casbin isn't installed — the module itself is stdlib-only).

## Tests

40 tests, all green:

```console
$ python -m pytest tests/ -q
........................................                              [100%] 40 passed
```

| File | Tests | Covers |
|---|---:|---|
| `test_handlers.py` | 17 | Unit tests: happy path, wrong token counts, cycles, duplicates, unknown templates, field-labelling regressions |
| `test_real_data_smoke.py` | 8 | Real example configs from `casbin/casbin/examples` (basic, rbac, domains, keymatch, abac) |
| `test_real_world_scenarios.py` | 7 | Realistic configurations with planted defects |
| `test_cross_validation_casbin.py` | 5 | Verdict agreement with the actual `casbin` library |
| `stress_test.py` | 3 | 5000+ rule policy — all planted issues found, ~26 ms |

## Design notes

- **Stdlib only** — runs anywhere Python runs; no supply-chain surface
- **Zero side effects** — every command is read-only; configs are passed as strings
- **Evidence over guessing** — denials come with near-miss rules and only the fields that actually failed, never a false accusation
- **No network** — nothing leaves your machine

## License

MIT © 2026 tlyyxjz
