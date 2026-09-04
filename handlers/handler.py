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
    # Drop a UTF-8 BOM if present. Files saved by Windows editors / Excel /
    # copied from the web often start with U+FEFF, which would otherwise make
    # the first [section] header fail to match and silently break everything.
    model_conf = model_conf.replace("\ufeff", "")
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
    """Return the variable names of a definition section, in declaration order.

    Order matters: callers zip this against request/policy value vectors, so a
    set (arbitrary iteration order) would silently mislabel every field.
    """
    out = []
    for expr in (sections.get(section) or {}).values():
        for tok in expr.split(","):
            tok = tok.strip()
            if not tok:
                continue
            name = tok.split("=")[-1].strip()
            if name and name not in out:
                out.append(name)
    return out


# --------------------------------------------------------------------------
# policy.csv parsing
# --------------------------------------------------------------------------

def parse_policy(policy_csv):
    """Return (rules, comments) where rules = [{'line': n, 'tokens': [...],
    'rule_type': 'p'|'g', 'domain': str|None}] blank/comment lines skipped."""
    # Strip UTF-8 BOM (see parse_model) — a leading BOM turns the first rule's
    # type token into e.g. '\ufeffp', which would be skipped as a non-p/g rule.
    policy_csv = policy_csv.replace("\ufeff", "")
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
    """解释 enforce 为什么返回 false。支持 ACL/RBAC 和 domains 多租户模型。

    原理：按 request_definition / policy_definition 的字段定义对齐请求值与
    策略值，逐字段比对（含角色展开和通配符），给出归因。
    """
    sections, _ = parse_model(inputs["model_conf"])
    rules = parse_policy(inputs["policy_csv"])
    sub, obj, act = inputs["sub"], inputs["obj"], inputs["act"]
    dom = inputs.get("dom") or inputs.get("domain")

    req_vars = list(_def_vars(sections, "request_definition"))
    pol_vars = list(_def_vars(sections, "policy_definition"))

    # 角色继承参数：g = _,_ 是 2 元；domains 模型 g = _,_,_ 是 3 元
    g_params = 2
    for expr in (sections.get("role_definition") or {}).values():
        n = len([t for t in expr.split(",") if t.strip()])
        g_params = max(g_params, n)

    # 角色展开（domains 模型继承按域隔离：g, sub, role, dom）
    roles_of = {sub}
    changed = True
    while changed:
        changed = False
        for r in rules:
            if r["rule_type"] == "g" and len(r["tokens"]) >= 3:
                child, parent = r["tokens"][1], r["tokens"][2]
                rdom = r["tokens"][3] if len(r["tokens"]) >= 4 else None
                if child in roles_of:
                    if rdom and dom and rdom != dom:
                        continue
                    if parent not in roles_of:
                        roles_of.add(parent)
                        changed = True

    # 请求值向量（按 request_definition 字段顺序）
    if len(req_vars) == 4 and dom:
        rvals = [sub, dom, obj, act]
    else:
        rvals = [sub, obj, act]

    def field_match(pv, rv):
        return pv == rv or pv == "*"

    sub_pos = 0 if pol_vars and "sub" in pol_vars[0].lower() else None
    matcher = next(iter((sections.get("matchers") or {}).values()), "")
    candidates, failures = [], []
    matched_any = False
    for r in rules:
        if r["rule_type"] != "p":
            continue
        pvals = r["tokens"][1:]
        if len(pvals) != len(rvals):
            continue  # token 数不匹配的规则由 diagnose 负责报错
        checks = []
        for idx, (pv, rv) in enumerate(zip(pvals, rvals)):
            ok = pv == rv or pv == "*"
            if not ok and idx == 0 and pv in roles_of:
                ok = True  # subject 位置走角色展开
            checks.append(ok)
        if all(checks):
            matched_any = True
            candidates.append({"line": r["line"], "rule": ",".join(r["tokens"])})
        else:
            why = []
            for idx, (pv, rv) in enumerate(zip(pvals, rvals)):
                if pv == rv or pv == "*":
                    continue
                # subject 位置若通过角色继承匹配上，就不是失败原因，不能报
                if idx == 0 and pv in roles_of:
                    continue
                why.append(f"{pol_vars[idx] if idx < len(pol_vars) else idx} mismatch: policy has '{pv}', request is '{rv}'")
            if sum(checks) >= len(pvals) - 1:
                failures.append({"line": r["line"], "rule": ",".join(r["tokens"]), "why_not": why})

        matcher = next(iter((sections.get("matchers") or {}).values()), "")

    return {
        "request": dict(zip(req_vars, rvals)) if len(req_vars) == len(rvals) else {"sub": sub, "obj": obj, "act": act},
        "roles_considered": sorted(roles_of),
        "allowed": bool(candidates),
        "matching_rules": candidates,
        "near_misses": failures[:10],
        "matcher": matcher,
        "advice": _deny_advice(matched_any, roles_of, sub, failures),
    }


def _deny_advice(matched, roles_of, sub, failures):
    # 下游 #730: 当 near-miss 是 subject 字段不匹配(角色未用 g 链上)时, 直接提示补 g 赋值
    sub_mismatch = any("sub mismatch" in w for f in (failures or []) for w in f.get("why_not", []))
    g_hint = (" The subject field does not match: if '%s' should inherit the policy's role, "
              "add a g assignment (e.g. g, %s, <role>)." % (sub, sub)) if sub_mismatch else ""
    if matched:
        return "Request matches policy; if it is still denied, check policy_effect (e.g. a priority/deny effect) and the matcher expression."
    if len(roles_of) > 1:
        return "No policy matched even after expanding roles %s. Either add a p rule for one of these subjects, or check the matcher.%s" % (sorted(roles_of - {sub}), g_hint)
    if failures:
        return "Closest rule(s) listed in near_misses - the request fails on the listed field(s).%s" % g_hint
    return "No p rules relate to this request at all. Add a policy rule covering '%s'." % sub


def diagnose(inputs, context=None):
    """Full check-up combining every static check."""
    issues = []
    model_conf = inputs["model_conf"]
    policy_csv = inputs["policy_csv"]

    mv = validate_model({"model_conf": model_conf})
    for i in mv["issues"]:
        issues.append({"check": "validate_model", **i})

    cyc = detect_role_cycle({"policy_csv": policy_csv})
    for c in cyc["cycles"]:
        issues.append({"check": "role_cycle", "line": None, "severity": "error",
                       "message": "role inheritance cycle: " + " -> ".join(c)})

    # lint_policy 一次性覆盖 duplicates / token_count / dead-assignment /
    # orphan-policy / domain-mismatch, 避免与 diagnose 重复计数
    lint = lint_policy({"model_conf": model_conf, "policy_csv": policy_csv})
    for f in lint["findings"]:
        issues.append({"check": f["check"],
                       "line": f.get("line"),
                       "severity": f.get("severity", "warning"),
                       "message": f["message"]})

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


def lint_policy(inputs, context=None):
    """策略引用完整性检查 —— 定位「权限配了却不生效」类问题。

    对应下游真实 case: go-admin #730(配了权限但不生效)。
    检查项:
      1. dead_assignment: g 赋值的角色没有任何 p 规则 -> 授权无效
      2. orphan_policy:   p 规则的 subject 不可达(无用户经 g 链到它, 也非直接请求主体)
      3. domain_mismatch: domains 模型下, p 规则所在域无对应 g 链接
      4. duplicates:      重复 p 规则(AddPolicies 遇重复会失败并可能清空角色权限)
      5. token_count:     p 规则 token 数与 model 定义不符
    无 g 规则的 basic/ACL 模型下, p.sub 即直接请求主体, 不报 orphan/dead。
    """
    sections, _ = parse_model(inputs["model_conf"])
    rules = parse_policy(inputs["policy_csv"])
    pol_vars = list(_def_vars(sections, "policy_definition"))

    # 角色继承参数: g = _,_ 是 2 元; domains 模型 g = _,_,_ 是 3 元
    g_params = 2
    for expr in (sections.get("role_definition") or {}).values():
        n = len([t for t in expr.split(",") if t.strip()])
        g_params = max(g_params, n)

    has_roles = bool(sections.get("role_definition")) or g_params >= 3

    # g 继承图
    edges = defaultdict(set)
    g_children, g_parents = set(), set()
    for r in rules:
        if r["rule_type"] != "g" or len(r["tokens"]) < 3:
            continue
        child, parent = r["tokens"][1], r["tokens"][2]
        g_children.add(child)
        g_parents.add(parent)
        edges[child].add(parent)

    def reachable_from(child):
        seen, stack = set(), [child]
        while stack:
            cur = stack.pop()
            if cur in seen:
                continue
            seen.add(cur)
            stack.extend(edges.get(cur, ()))
        return seen

    # p 规则的 subject 集合
    p_subjects = set()
    for r in rules:
        if r["rule_type"] == "p" and len(r["tokens"]) >= 2:
            p_subjects.add(r["tokens"][1])

    findings = []

    # 1 + 2: 仅在 RBAC / domains 模型(存在角色)时检查 dead/orphan
    if has_roles:
        reachable = set()
        for u in g_children:
            reachable |= reachable_from(u)
        for parent in sorted(g_parents):
            if parent not in p_subjects:
                findings.append({
                    "check": "dead_assignment", "severity": "warning",
                    "subject": parent,
                    "message": "role '%s' is assigned to users via g, but no p rule grants it any permission — the assignment grants nothing" % parent,
                })
        for subj in sorted(p_subjects):
            if subj in reachable or subj in g_children:
                continue
            findings.append({
                "check": "orphan_policy", "severity": "warning",
                "subject": subj,
                "message": "p rule subject '%s' is unreachable: no g assignment links any user to it (and it is not a direct request subject) — the rule can never allow anyone" % subj,
            })

    # 3: domains 模型域不匹配
    if g_params >= 3 and len(pol_vars) >= 3:
        p_doms = set()
        g_doms = set()
        for r in rules:
            if r["rule_type"] == "p" and len(r["tokens"]) >= 4:
                p_doms.add(r["tokens"][2])  # p = sub, dom, obj, act
            if r["rule_type"] == "g" and len(r["tokens"]) >= 4:
                g_doms.add(r["tokens"][3])  # g = _, _, dom
        for dom in sorted(p_doms):
            if dom not in g_doms:
                findings.append({
                    "check": "domain_mismatch", "severity": "warning",
                    "domain": dom,
                    "message": "p rules exist for domain '%s' but no g (role) assignment exists in that domain — no user can reach them" % dom,
                })

    # 4: 重复 p 规则
    dup = detect_duplicates({"policy_csv": inputs["policy_csv"]})
    for d in dup["duplicates"]:
        findings.append({
            "check": "duplicates", "severity": "warning",
            "line": d["line"],
            "message": "duplicate of line %d: %s (AddPolicies fails on duplicates and can wipe role permissions)" % (d["first_seen_line"], d["rule"]),
        })

    # 5: arity 不匹配
    expected = _policy_token_count(sections)
    for r in rules:
        if r["rule_type"] == "p" and expected and len(r["tokens"]) != expected:
            findings.append({
                "check": "token_count", "severity": "error",
                "line": r["line"],
                "message": "rule '%s' has %d tokens, model expects %d" % (",".join(r["tokens"]), len(r["tokens"]), expected),
            })

    errors = sum(1 for f in findings if f.get("severity") == "error")
    warnings = sum(1 for f in findings if f.get("severity") == "warning")
    return {
        "healthy": errors == 0,
        "findings": findings,
        "summary": "%d finding(s): %d error(s), %d warning(s)" % (len(findings), errors, warnings),
    }
