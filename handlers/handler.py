"""Handlers for tlyyxjz/casbin-config-doctor.

Pure-stdlib Casbin configuration diagnostics. Each command declared in
module.json maps to a top-level function here. No third-party imports so the
module installs and runs anywhere Python 3 runs.
"""
import re
from collections import defaultdict

# --------------------------------------------------------------------------
# model.conf parsing
# --------------------------------------------------------------------------

_SECTION_RE = re.compile(r"^\s*\[([a-z_]+)\]\s*$")
_KV_RE = re.compile(r"^\s*([A-Za-z_]+)\s*=\s*(.+?)\s*$")

REQUIRED_SECTIONS = {
    "request_definition": "r",
    "policy_definition": "p",
    "policy_effect": "e",
    "matchers": "m",
}


def parse_model(model_conf):
    """Parse model.conf into {section: {key: value}} plus syntax issues."""
    sections = {}
    issues = []
    current = None
    for lineno, raw in enumerate(model_conf.splitlines(), 1):
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        m = _SECTION_RE.match(line)
        if m:
            current = m.group(1)
            sections.setdefault(current, {})
            continue
        if current is None:
            issues.append({"line": lineno, "severity": "error",
                           "message": "key=value before any [section] header"})
            continue
        kv = _KV_RE.match(line)
        if not kv:
            issues.append({"line": lineno, "severity": "error",
                           "message": "expected 'key = value' inside [%s]" % current})
            continue
        sections[current][kv.group(1)] = kv.group(2)
    return sections, issues


def validate_model(inputs, context=None):
    """Check model.conf structure and the presence of required definitions."""
    model_conf = inputs["model_conf"]
    sections, issues = parse_model(model_conf)

    for section in REQUIRED_SECTIONS:
        if section not in sections:
            issues.append({"line": None, "severity": "error",
                           "message": "missing required section [%s]" % section})
        elif not sections[section]:
            issues.append({"line": None, "severity": "error",
                           "message": "section [%s] is empty" % section})

    if "role_definition" in sections and not sections["role_definition"]:
        issues.append({"line": None, "severity": "warning",
                       "message": "[role_definition] present but empty"})

    # cross-check: matcher/effect references must exist in request/policy defs
    req_vars = _def_vars(sections, "request_definition")
    pol_vars = _def_vars(sections, "policy_definition")
    for mname, expr in (sections.get("matchers") or {}).items():
        for var in re.findall(r"\b([rp]\.\w+)", expr):
            dotvar = var.split(".")[1]
            if var.startswith("r.") and dotvar not in req_vars:
                issues.append({"line": None, "severity": "error",
                               "message": "matcher '%s' uses %s but request_definition does not define it" % (mname, var)})
            if var.startswith("p.") and dotvar not in pol_vars:
                issues.append({"line": None, "severity": "error",
                               "message": "matcher '%s' uses %s but policy_definition does not define it" % (mname, var)})

    errors = [i for i in issues if i["severity"] == "error"]
    return {
        "valid": len(errors) == 0,
        "sections_found": sorted(sections.keys()),
        "issues": issues,
        "summary": "%d issue(s): %d error(s), %d warning(s)" % (
            len(issues), len(errors), len(issues) - len(errors)),
    }


def _def_vars(sections, section):
    out = set()
    for expr in (sections.get(section) or {}).values():
        for tok in expr.split(","):
            tok = tok.strip()
            if tok:
                out.add(tok.split("=")[-1].strip())
    return out


# --------------------------------------------------------------------------
# policy.csv parsing
# --------------------------------------------------------------------------

def parse_policy(policy_csv):
    """Return (rules, comments) where rules = [{'line': n, 'tokens': [...],
    'rule_type': 'p'|'g', 'domain': str|None}] blank/comment lines skipped."""
    rules = []
    for lineno, raw in enumerate(policy_csv.splitlines(), 1):
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        tokens = [t.strip() for t in line.split(",")]
        rule_type = tokens[0]
        rules.append({
            "line": lineno,
            "tokens": tokens,
            "rule_type": rule_type,
            "domain": tokens[2] if rule_type == "g" and len(tokens) > 3 else None,
        })
    return rules


def _policy_token_count(sections):
    """Token count implied by policy_definition (p = sub, obj, act -> 3 + 1 tag)."""
    pol = (sections.get("policy_definition") or {})
    for expr in pol.values():
        n = len([t for t in expr.split(",") if t.strip()])
        if n:
            return n + 1
    return None


# --------------------------------------------------------------------------
# commands
# --------------------------------------------------------------------------

def check_policy(inputs, context=None):
    sections, _ = parse_model(inputs["model_conf"])
    n = _policy_token_count(sections)
    tokens = [t.strip() for t in inputs["policy_line"].split(",")]
    if n is None:
        return {"ok": False, "reason": "model has no [policy_definition] p = ... line"}
    if tokens[0] != "p":
        # g rules are legal in policy files too
        if tokens[0] == "g":
            return {"ok": True, "rule_type": "g", "tokens": tokens,
                    "note": "role rule; token count is not fixed by policy_definition"}
        return {"ok": False, "reason": "rule must start with 'p' (or 'g'), got '%s'" % tokens[0]}
    ok = len(tokens) == n
    return {
        "ok": ok,
        "rule_type": "p",
        "expected_tokens": n,
        "actual_tokens": len(tokens),
        "tokens": tokens,
        "reason": None if ok else "expected %d comma-separated tokens (including leading 'p'), got %d" % (n, len(tokens)),
    }


def detect_duplicates(inputs, context=None):
    rules = parse_policy(inputs["policy_csv"])
    seen = {}
    duplicates = []
    for r in rules:
        key = ",".join(r["tokens"])
        if key in seen:
            duplicates.append({"line": r["line"], "first_seen_line": seen[key],
                               "rule": key})
        else:
            seen[key] = r["line"]
    return {"duplicates": duplicates,
            "total_rules": len(rules),
            "summary": "%d duplicate rule(s) found" % len(duplicates)}


def detect_role_cycle(inputs, context=None):
    policy_csv = inputs["policy_csv"]
    prefix = inputs.get("role_rule", "g")
    edges = defaultdict(set)
    for r in parse_policy(policy_csv):
        if r["rule_type"] == prefix and len(r["tokens"]) >= 3:
            child, parent = r["tokens"][1], r["tokens"][2]
            edges[child].add(parent)

    cycles = []
    visiting, done = set(), set()
    stack = []

    def dfs(node):
        visiting.add(node)
        stack.append(node)
        for nxt in sorted(edges.get(node, ())):
            if nxt in visiting:
                i = stack.index(nxt)
                cycles.append(stack[i:] + [nxt])
            elif nxt not in done:
                dfs(nxt)
        stack.pop()
        visiting.discard(node)
        done.add(node)

    for node in sorted(edges):
        if node not in done:
            dfs(node)
    return {"cycles": cycles,
            "summary": "%d role cycle(s) found" % len(cycles)}


def explain_deny(inputs, context=None):
    sections, _ = parse_model(inputs["model_conf"])
    rules = parse_policy(inputs["policy_csv"])
    sub, obj, act = inputs["sub"], inputs["obj"], inputs["act"]

    pol_vars = list(_def_vars(sections, "policy_definition"))
    if len(pol_vars) < 3:
        return {"allowed": None, "reason": "cannot explain: policy_definition needs at least sub, obj, act"}

    subject_var, object_var, action_var = pol_vars[0], pol_vars[1], pol_vars[2]

    # role expansion from g rules (single domain)
    roles_of = {sub}
    changed = True
    while changed:
        changed = False
        for r in rules:
            if r["rule_type"] == "g" and len(r["tokens"]) >= 3 \
                    and r["tokens"][1] in roles_of and r["tokens"][2] not in roles_of:
                roles_of.add(r["tokens"][2])
                changed = True

    candidates, failures = [], []
    matched_any = False
    for r in rules:
        if r["rule_type"] != "p" or len(r["tokens"]) < 4:
            continue
        p_sub, p_obj, p_act = r["tokens"][1], r["tokens"][2], r["tokens"][3]
        ok_sub = p_sub == sub or p_sub in roles_of or p_sub == "*"
        ok_obj = p_obj == obj or p_obj == "*"
        ok_act = p_act == act or p_act == "*"
        if ok_sub and ok_obj and ok_act:
            matched_any = True
            candidates.append({"line": r["line"], "rule": ",".join(r["tokens"])})
        else:
            why = []
            if not ok_sub:
                why.append("subject mismatch: policy has '%s', request is '%s' (roles: %s)"
                           % (p_sub, sub, sorted(roles_of - {sub})))
            if not ok_obj:
                why.append("object mismatch: policy has '%s', request is '%s'" % (p_obj, obj))
            if not ok_act:
                why.append("action mismatch: policy has '%s', request is '%s'" % (p_act, act))
            # only report near-misses (2 of 3 fields matched) to keep output useful
            if sum(1 for ok in (ok_sub, ok_obj, ok_act) if ok) >= 2:
                failures.append({"line": r["line"], "rule": ",".join(r["tokens"]),
                                 "why_not": why})

    matcher = next(iter((sections.get("matchers") or {}).values()), "")
    allow_style = "hasAllow" if "hasAllow" in sections.get("policy_effect", {}).get(
        next(iter(sections.get("policy_effect", {})), ""), "") or "!deny" in str(
        sections.get("policy_effect", {})) else "some"

    return {
        "request": {"sub": sub, "obj": obj, "act": act},
        "roles_considered": sorted(roles_of),
        "allowed": matched_any,
        "matching_rules": candidates,
        "near_misses": failures[:10],
        "matcher": matcher,
        "advice": _deny_advice(matched_any, roles_of, sub, failures),
    }


def _deny_advice(matched, roles_of, sub, failures):
    if matched:
        return "Request matches policy; if it is still denied, check policy_effect (e.g. a priority/deny effect) and the matcher expression."
    if len(roles_of) > 1:
        return "No policy matched even after expanding roles %s. Either add a p rule for one of these subjects, or check the matcher." % sorted(roles_of - {sub})
    if failures:
        return "Closest rule(s) listed in near_misses - the request fails on the listed field(s). Add a matching p rule or fix the request."
    return "No p rules relate to this request at all. Add a policy rule covering '%s'." % sub


def diagnose(inputs, context=None):
    """Full check-up combining every static check."""
    issues = []
    model_conf = inputs["model_conf"]
    policy_csv = inputs["policy_csv"]

    mv = validate_model({"model_conf": model_conf})
    for i in mv["issues"]:
        issues.append({"check": "validate_model", **i})

    sections, _ = parse_model(model_conf)
    expected = _policy_token_count(sections)
    rules = parse_policy(policy_csv)
    for r in rules:
        if r["rule_type"] == "p" and expected and len(r["tokens"]) != expected:
            issues.append({"check": "token_count", "line": r["line"], "severity": "error",
                           "message": "rule '%s' has %d tokens, model expects %d"
                                      % (",".join(r["tokens"]), len(r["tokens"]), expected)})

    dup = detect_duplicates({"policy_csv": policy_csv})
    for d in dup["duplicates"]:
        issues.append({"check": "duplicates", "line": d["line"], "severity": "warning",
                       "message": "duplicate of line %d: %s" % (d["first_seen_line"], d["rule"])})

    cyc = detect_role_cycle({"policy_csv": policy_csv})
    for c in cyc["cycles"]:
        issues.append({"check": "role_cycle", "line": None, "severity": "error",
                       "message": "role inheritance cycle: " + " -> ".join(c)})

    # exact-duplicate subject+object with conflicting actions is fine, but
    # identical p rules with different effects would be - kept simple for v0.1

    errors = sum(1 for i in issues if i.get("severity") == "error")
    warnings = sum(1 for i in issues if i.get("severity") == "warning")
    return {
        "healthy": errors == 0,
        "issues": issues,
        "summary": "%d issue(s): %d error(s), %d warning(s)"
                   % (len(issues), errors, warnings),
    }


_TEMPLATES = {
    "rbac": {
        "keywords": ("rbac", "role", "admin", "viewer", "editor"),
        "model": """[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act

[role_definition]
g = _, _

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = g(r.sub, p.sub) && r.obj == p.obj && r.act == p.act
""",
        "policy": """p, admin, *, *
p, editor, reports, read
p, editor, reports, write
p, viewer, reports, read

g, alice, admin
g, bob, editor
g, carol, viewer
""",
    },
    "restful": {
        "keywords": ("rest", "api", "endpoint", "http", "get", "post"),
        "model": """[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act

[role_definition]
g = _, _

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = g(r.sub, p.sub) && keyMatch2(r.obj, p.obj) && regexMatch(r.act, p.act)
""",
        "policy": """p, admin, /api/*, (GET)|(POST)|(PUT)|(DELETE)
p, user, /api/profile.*, GET

g, alice, admin
g, bob, user
""",
    },
    "abac": {
        "keywords": ("abac", "attribute", "owner", "department"),
        "model": """[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = r.sub == r.obj.owner && r.act == p.act
""",
        "policy": """p, *, *, read
p, *, *, write
""",
    },
}


def generate(inputs, context=None):
    """Pick the closest template from a plain-language requirement."""
    req = inputs["requirement"].lower()
    scored = []
    for name, t in _TEMPLATES.items():
        score = sum(1 for k in t["keywords"] if k in req)
        if score:
            scored.append((score, name))
    if not scored:
        return {"matched": None,
                "advice": "No template matched. Supported patterns: rbac, restful, abac. "
                          "Mention roles / REST endpoints / attribute ownership in the requirement."}
    scored.sort(reverse=True)
    name = scored[0][1]
    t = _TEMPLATES[name]
    return {"matched": name,
            "model_conf": t["model"],
            "policy_csv": t["policy"],
            "note": "Template output - edit users in policy.csv (g rules) to match your organization."}


def compare(inputs, context=None):
    def rule_set(text):
        rules = {}
        for r in parse_policy(text):
            rules.setdefault(",".join(r["tokens"]), []).append(r["line"])
        return rules

    a, b = rule_set(inputs["policy_a"]), rule_set(inputs["policy_b"])
    return {
        "added": sorted(set(b) - set(a)),
        "removed": sorted(set(a) - set(b)),
        "unchanged": sorted(set(a) & set(b)),
    }
