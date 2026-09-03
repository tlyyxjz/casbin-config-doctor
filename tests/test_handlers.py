"""Offline tests for casbin-config-doctor handlers. Run: python -m pytest tests/"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "handlers"))
import handler  # noqa: E402

GOOD_MODEL = """[request_definition]
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

BROKEN_MODEL = """[request_definition]
r = sub, obj, act

[matchers]
m = g(r.sub, p.sub) && r.obj == p.obj && r.act == p.act
"""

POLICY = """p, admin, data1, read
p, admin, data1, write
p, alice, data2, read
g, alice, admin

p, admin, data1, read
"""


def test_validate_model_good():
    out = handler.validate_model({"model_conf": GOOD_MODEL})
    assert out["valid"] is True, out
    assert out["issues"] == []


def test_validate_model_missing_sections():
    out = handler.validate_model({"model_conf": BROKEN_MODEL})
    assert out["valid"] is False
    msgs = " ".join(i["message"] for i in out["issues"])
    assert "policy_definition" in msgs and "policy_effect" in msgs


def test_check_policy_ok():
    out = handler.check_policy({"model_conf": GOOD_MODEL, "policy_line": "p, alice, data1, read"})
    assert out["ok"] is True and out["expected_tokens"] == 4


def test_check_policy_wrong_token_count():
    out = handler.check_policy({"model_conf": GOOD_MODEL, "policy_line": "p, alice, data1"})
    assert out["ok"] is False and out["actual_tokens"] == 3


def test_detect_duplicates():
    out = handler.detect_duplicates({"policy_csv": POLICY})
    assert out["duplicates"][0]["rule"] == "p,admin,data1,read"
    assert out["duplicates"][0]["first_seen_line"] == 1


def test_role_cycle_detected():
    cyclic = "g, a, b\ng, b, c\ng, c, a\n"
    out = handler.detect_role_cycle({"policy_csv": cyclic})
    assert len(out["cycles"]) == 1
    assert out["cycles"][0][0] == out["cycles"][0][-1]


def test_no_cycle_in_clean_policy():
    out = handler.detect_role_cycle({"policy_csv": POLICY})
    assert out["cycles"] == []


def test_explain_deny_role_expansion():
    # alice denied on data1:write? admin role grants it -> should be allowed
    out = handler.explain_deny({"model_conf": GOOD_MODEL, "policy_csv": POLICY,
                                "sub": "alice", "obj": "data1", "act": "write"})
    assert out["allowed"] is True
    assert "admin" in out["roles_considered"]


def test_explain_deny_near_miss():
    out = handler.explain_deny({"model_conf": GOOD_MODEL, "policy_csv": POLICY,
                                "sub": "alice", "obj": "data2", "act": "write"})
    assert out["allowed"] is False
    assert out["near_misses"], "expected a near-miss on data2:read"


def test_diagnose_finds_all_issue_types():
    bad_policy = POLICY + "p, bob, data3\ng, x, y\ng, y, x\n"
    out = handler.diagnose({"model_conf": GOOD_MODEL, "policy_csv": bad_policy})
    checks = {i["check"] for i in out["issues"]}
    assert "token_count" in checks
    assert "duplicates" in checks
    assert "role_cycle" in checks
    assert out["healthy"] is False


def test_generate_rbac():
    out = handler.generate({"requirement": "Simple RBAC with admin and viewer roles"})
    assert out["matched"] == "rbac"
    # generated model must itself validate cleanly
    v = handler.validate_model({"model_conf": out["model_conf"]})
    assert v["valid"] is True, v


def test_generate_unknown():
    out = handler.generate({"requirement": "quantum blockchain synergy"})
    assert out["matched"] is None


def test_compare():
    a = "p, u1, d1, read\np, u2, d1, read\n"
    b = "p, u1, d1, read\np, u3, d1, write\n"
    out = handler.compare({"policy_a": a, "policy_b": b})
    assert out["added"] == ["p,u3,d1,write"]
    assert out["removed"] == ["p,u2,d1,read"]
    assert out["unchanged"] == ["p,u1,d1,read"]


DOMAIN_MODEL = """[request_definition]
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

DOMAIN_POLICY = """p, admin, domain1, data1, read
g, alice, admin, domain1
"""


def test_explain_deny_labels_request_fields_in_model_order():
    """Regression: _def_vars returned a set, so zip(req_vars, rvals) mislabelled
    every field (e.g. sub/obj/act rotated). Field names must follow the order
    declared in request_definition."""
    out = handler.explain_deny({
        "model_conf": GOOD_MODEL,
        "policy_csv": "p, alice, data1, read\n",
        "sub": "alice", "obj": "data2", "act": "read",
    })
    assert out["request"] == {"sub": "alice", "obj": "data2", "act": "read"}, out["request"]


def test_explain_deny_near_miss_names_the_failing_field():
    """The near-miss reason must name the field that actually failed."""
    out = handler.explain_deny({
        "model_conf": GOOD_MODEL,
        "policy_csv": "p, alice, data1, read\n",
        "sub": "alice", "obj": "data2", "act": "read",
    })
    reasons = " ".join(r for m in out["near_misses"] for r in m["why_not"])
    assert "obj mismatch" in reasons, out["near_misses"]
    assert "policy has 'data1'" in reasons, out["near_misses"]


def test_explain_deny_domains_labels_dom_field():
    """Multi-tenant models declare r = sub, dom, obj, act; dom must be labelled
    as dom, not rotated into another position."""
    out = handler.explain_deny({
        "model_conf": DOMAIN_MODEL,
        "policy_csv": DOMAIN_POLICY,
        "sub": "alice", "obj": "data2", "act": "read", "dom": "domain1",
    })
    assert out["request"] == {
        "sub": "alice", "dom": "domain1", "obj": "data2", "act": "read",
    }, out["request"]
    reasons = " ".join(r for m in out["near_misses"] for r in m["why_not"])
    assert "obj mismatch" in reasons, out["near_misses"]


def test_explain_deny_does_not_blame_role_inherited_subject():
    """Regression: when the request subject reaches the policy subject through a
    g (role) rule, the subject position DID match. Reporting 'sub mismatch'
    there is a false accusation that hides the real failing field."""
    out = handler.explain_deny({
        "model_conf": GOOD_MODEL,
        "policy_csv": "p, admin, data2, write\ng, alice, admin\n",
        "sub": "alice", "obj": "data2", "act": "read",
    })
    reasons = " ".join(r for m in out["near_misses"] for r in m["why_not"])
    assert "sub mismatch" not in reasons, out["near_misses"]
    assert "act mismatch" in reasons, out["near_misses"]
    assert out["allowed"] is False
