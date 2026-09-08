# Casbin Config Doctor

Diagnose why Casbin's `enforce()` returns `false` — and which exact line and field failed.

## Who it's for

Backend developers running [Casbin](https://github.com/casbin/casbin) (20k+ stars) in production who have lost an afternoon to a request that is silently denied.

Concretely: a three-person SaaS team ships RBAC, adds `g, alice, admin`, and `alice` still cannot read `data2`. Nothing errors. Nothing logs. The matcher is 40 characters long and one token in it is wrong. Finding that by hand means bisecting config files and re-reading docs. This does it in one command.

## Install

```bash
railcall market install tlyyxjz/casbin-config-doctor
```

Stdlib-only Python 3.9+. No credentials, no network calls, no setup — `auth: none`. Runs entirely on your own files.

## Example

```console
$ railcall run casbin-config-doctor explain-deny \
    --model model.conf --policy policy.csv \
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
advice: add a p rule for one of these subjects, or check the matcher
```

Note what it does *not* report: no `sub` mismatch, because `alice` reaches `admin` through `g`. Only genuinely failing fields are listed.

## Eight commands

| Command | Purpose |
|---|---|
| `diagnose` | Full check-up: model syntax, token counts, duplicates, role cycles |
| `explain-deny` | Why a request was denied, with near-miss rules and failing field |
| `validate-model` | `model.conf` structure, required sections, matcher↔definition cross-check |
| `check-policy` | One policy line's token count vs the model definition |
| `detect-duplicates` | Duplicate rules with first-seen line numbers |
| `detect-role-cycle` | Inheritance cycles in `g` rules (DFS) |
| `generate` | Plain-language requirement → model + policy (RBAC / RESTful / ABAC) |
| `compare` | Diff two policy files: added / removed / unchanged |

Multi-tenant (`domains`) models are supported: role inheritance resolves per-domain, so a role granted in one tenant does not leak into another.

## Correctness

`explain-deny` verdicts are cross-validated against the real `casbin` library — allow/deny agrees with `casbin.Enforcer.enforce()` on the official example configs. 40 automated tests green, including a 5,000-rule stress run (~26 ms).

## Known limitations

- Static analysis: it does not execute your matcher against a live enforcer, so custom matcher functions are parsed, not evaluated.
- `generate` produces templates for RBAC / RESTful / ABAC only; anything exotic needs hand-editing.
- Verdict cross-validation requires `pip install casbin` and is skipped without it — the module itself stays stdlib-only.
- Reads local files only; no remote repo or SaaS integration.

## Links

- Marketplace: https://railcall.ai/marketplace/tlyyxjz/casbin-config-doctor
- Source + tests: https://github.com/tlyyxjz/casbin-config-doctor
- Online demo (nothing uploaded): https://tlyyxjz.github.io/casbin-doctor-demo/
