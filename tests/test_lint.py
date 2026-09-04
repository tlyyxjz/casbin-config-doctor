"""Policy reference-integrity lint + explain-deny g-link hint.

Real-world fixtures derived from the downstream casbin issues we engaged:
- go-admin #730  : permission configured but not effective
- gva #1403/#1533: duplicate api rules -> AddPolicies fails
- domains models : p rules in a domain with no g link
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from handlers import handler

RBAC_MODEL = """[request_definition]
r = sub, obj, act
[policy_definition]
p = sub, obj, act
[role_definition]
g = _, _
[policy_effect]
e = some(where (p.eft == allow))
[matchers]
m = g(r.sub, p.sub) && r.obj == p.obj && r.act == p.act
"""

BASIC_MODEL = """[request_definition]
r = sub, obj, act
[policy_definition]
p = sub, obj, act
[policy_effect]
e = some(where (p.eft == allow))
[matchers]
m = r.sub == p.sub && r.obj == p.obj && r.act == p.act
"""

DOMAINS_MODEL = """[request_definition]
r = sub, dom, obj, act
[policy_definition]
p = sub, dom, obj, act
[role_definition]
g = _, _, _
[policy_effect]
e = some(where (p.eft == allow))
[matchers]
m = g(r.sub, p.sub, r.dom) && r.dom == p.dom && r.obj == p.obj && r.act == p.act
"""


def _lint(model, policy):
    return handler.lint_policy({"model_conf": model, "policy_csv": policy})


def test_lint_dead_assignment_goadmin730():
    # 角色被 g 赋值但没有任何 p 规则 -> 授权无效 (go-admin #730 变体)
    policy = "p, admin, /api/x, GET\ng, alice, admin\ng, bob, superadmin\n"
    out = _lint(RBAC_MODEL, policy)
    dead = [f for f in out["findings"] if f["check"] == "dead_assignment"]
    assert len(dead) == 1, out["findings"]
    assert dead[0]["subject"] == "superadmin"
    # admin 有 p 规则, 不应报 orphan
    assert not any(f["check"] == "orphan_policy" for f in out["findings"])


def test_lint_orphan_policy():
    # p.sub 是角色但没有任何用户经 g 链到它 -> 规则永不可达
    policy = "g, alice, admin\np, admin, /api/admin, GET\np, ghost, /api/ghost, GET\n"
    out = _lint(RBAC_MODEL, policy)
    orphan = [f for f in out["findings"] if f["check"] == "orphan_policy"]
    assert len(orphan) == 1, out["findings"]
    assert orphan[0]["subject"] == "ghost"
    assert not any(f["check"] == "dead_assignment" for f in out["findings"])


def test_lint_domain_mismatch():
    # domains 模型: p 规则在 dom2, 但 dom2 没有任何 g 链接
    policy = "p, admin, dom1, /api/x, GET\ng, alice, admin, dom1\np, admin, dom2, /api/y, GET\n"
    out = _lint(DOMAINS_MODEL, policy)
    mm = [f for f in out["findings"] if f["check"] == "domain_mismatch"]
    assert len(mm) == 1, out["findings"]
    assert mm[0]["domain"] == "dom2"


def test_lint_duplicates_gva1403():
    # 重复 api 规则 -> AddPolicies 会失败 (gva #1403/#1533)
    policy = ("p, admin, /api/user/list, GET\n"
              "p, admin, /api/user/list, GET\n"
              "p, admin, /api/user/create, POST\n")
    out = _lint(RBAC_MODEL, policy)
    dup = [f for f in out["findings"] if f["check"] == "duplicates"]
    assert len(dup) == 1, out["findings"]


def test_lint_token_count_error():
    # p 规则 token 数与 model 定义不符 -> error
    policy = "p, admin, /api/x\n"
    out = _lint(BASIC_MODEL, policy)
    errs = [f for f in out["findings"] if f["check"] == "token_count"]
    assert len(errs) == 1, out["findings"]
    assert out["healthy"] is False


def test_lint_healthy_clean():
    # 干净的 RBAC 不应报任何 finding (无假阳性)
    policy = "p, admin, /api/x, GET\ng, alice, admin\n"
    out = _lint(RBAC_MODEL, policy)
    assert out["findings"] == [], out["findings"]
    assert out["healthy"] is True


def test_lint_role_cycle_does_not_hang():
    # 角色继承环不应让可达性分析死循环 (覆盖 cycle guard 分支)
    policy = "g, alice, admin\ng, admin, alice\np, admin, /api/x, GET\n"
    out = _lint(RBAC_MODEL, policy)
    assert not any(f["check"] == "orphan_policy" and f["subject"] == "admin"
                   for f in out["findings"]), out["findings"]


def test_explain_deny_glink_hint_goadmin730():
    # 用户没用 g 链到拥有该权限的角色 -> 建议补 g 赋值 (#730)
    policy = "p, admin, /api/secret, GET\ng, alice, admin\n"
    out = handler.explain_deny({
        "model_conf": RBAC_MODEL, "policy_csv": policy,
        "sub": "bob", "obj": "/api/secret", "act": "GET",
    })
    assert out["allowed"] is False
    assert out["near_misses"], "expected a near-miss on the subject field"
    assert any("sub mismatch" in w for m in out["near_misses"] for w in m["why_not"])
    assert "add a g assignment" in out["advice"], out["advice"]


def test_diagnose_includes_lint():
    # diagnose 全量体检应整合 lint 发现
    policy = "p, admin, /api/x, GET\ng, alice, admin\ng, bob, superadmin\n"
    out = handler.diagnose({"model_conf": RBAC_MODEL, "policy_csv": policy})
    assert any(i["check"] == "dead_assignment" for i in out["issues"]), out["issues"]
