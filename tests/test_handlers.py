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


# real garbage matcher from apache/casbin-editor #162 (filed by hsluoyz)
EDITOR162_MODEL = """[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = r.sub == p.sub22222 && r.obj11111 == ppppppp && r..act == p.act,,,,,,,,,,
"""


def test_validate_model_catches_editor162_garbage():
    out = handler.validate_model({"model_conf": EDITOR162_MODEL})
    msgs = " ".join(i["message"] for i in out["issues"])
    assert out["valid"] is False
    assert "p.sub22222" in msgs          # undefined policy var
    assert "r.obj11111" in msgs          # undefined request var
    assert "unrecognized identifier" in msgs      # bare unknown identifier
    assert "malformed member access" in msgs  # r..act
    assert "comma outside a function call" in msgs  # trailing ,,,,,


def test_validate_model_abac_nested_and_custom_fn_warns():
    # ABAC nested access r.obj.Owner must NOT be flagged;
    # unknown function call is a warning (may be registered via AddFunction)
    model = GOOD_MODEL.replace(
        "m = g(r.sub, p.sub) && r.obj == p.obj && r.act == p.act",
        "m = r.obj.Owner == r.sub && r.act == p.act && customFn(r.obj, p.obj)")
    out = handler.validate_model({"model_conf": model})
    msgs = " ".join(i["message"] for i in out["issues"])
    assert not any("r.obj.Owner" in i["message"] for i in out["issues"])
    assert "customFn" in msgs
    assert all(i["severity"] != "error" or "customFn" not in i["message"]
               for i in out["issues"])


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


def test_parse_handles_utf8_bom():
    """Files saved by Windows editors / Excel / copied from the web often start
    with a UTF-8 BOM (U+FEFF). A leading BOM must not break parsing — otherwise
    the first [section] header and the first policy rule are silently skipped,
    which made explain-deny return an empty near_misses for valid configs."""
    bom = "\ufeff"
    model = bom + GOOD_MODEL
    policy = bom + POLICY
    mv = handler.validate_model({"model_conf": model})
    assert mv["valid"] is True, mv
    parsed = handler.parse_policy(policy)
    assert parsed[0]["tokens"][0] == "p", parsed[0]["tokens"]
    # explain-deny must still attribute the near-miss on the BOM-prefixed input
    out = handler.explain_deny({"model_conf": model, "policy_csv": policy,
                                "sub": "alice", "obj": "data2", "act": "write"})
    assert out["allowed"] is False
    assert out["near_misses"], "BOM-prefixed config must still yield near-misses"


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


def test_parse_model_inline_semicolon_comments():
    """casbin Config accepts inline '; comments' (configparser style)."""
    conf = "[role_definition]\ng = _, _ ; domain roles\ng2 = _, _, _ ; resource roles\n"
    sections, issues = handler.parse_model(conf)
    assert issues == [], issues
    assert sections["role_definition"]["g"] == "_, _"
    assert sections["role_definition"]["g2"] == "_, _, _"


def test_parse_model_backslash_line_continuation():
    """Multi-line matchers with trailing backslashes must join into one value."""
    conf = (
        "[matchers]\n"
        "m = g(r.sub, p.sub) && \\\n"
        "    r.obj == p.obj && \\\n"
        "    r.act == p.act\n"
    )
    sections, issues = handler.parse_model(conf)
    assert issues == [], issues
    assert sections["matchers"]["m"] == \
        "g(r.sub, p.sub) && r.obj == p.obj && r.act == p.act"


def test_validate_model_numeric_keys_and_builtin_role_managers():
    """Keys with digits (g2/g3) are valid casbin role managers, not typos."""
    conf = (
        "[request_definition]\nr = sub, dom, obj, act\n"
        "[policy_definition]\np = sub, obj, act\n"
        "[role_definition]\ng = _, _\ng2 = _, _, _\ng3 = _, _\n"
        "[policy_effect]\ne = some(where (p.eft == allow))\n"
        "[matchers]\nm = g3(r.sub, \"*\") || g2(r.sub, p.sub, r.dom) && r.obj == p.obj && r.act == p.act\n"
    )
    out = handler.validate_model({"model_conf": conf})
    msgs = " ".join(i["message"] for i in out["issues"])
    assert "g2(...)" not in msgs and "g3(...)" not in msgs, out["issues"]
    assert out["valid"] is True, out["issues"]


# ---------------------------------------------------------------------------
# casbin-gateway 真实配置类：priority 效果 + 全 keyMatch + eft 列
# （Apache casbin-gateway object/permission_casbin.go 的 PermissionModelText）
# ---------------------------------------------------------------------------

GATEWAY_MODEL = """[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act, eft

[policy_effect]
e = priority(p.eft) || deny

[matchers]
m = keyMatch(r.sub, p.sub) && keyMatch(r.obj, p.obj) && keyMatch(r.act, p.act)
"""

GATEWAY_POLICY = """p, claude-code, tool:mcp/github, use, allow
p, claude-code, tool:mcp/*, use, deny
p, claude-code, tool:*, use, allow
p, claude-code, model:*, use, allow
"""


def _explain(model_conf, policy_csv, sub, obj, act):
    return handler.explain_deny({
        "model_conf": model_conf, "policy_csv": policy_csv,
        "sub": sub, "obj": obj, "act": act,
    })


def test_gateway_priority_exact_allow_wins_is_allowed():
    # 第 1 行精确 allow 按 priority 先赢，整体必须是 ALLOWED。
    # 回归：修复前 eft 列导致所有规则被跳过，误判 DENIED。
    out = _explain(GATEWAY_MODEL, GATEWAY_POLICY, "claude-code", "tool:mcp/github", "use")
    assert out["allowed"] is True, out["advice"]
    assert out["winning_rules"] and out["winning_rules"][0]["line"] == 1
    assert out["winning_rules"][0]["eft"] == "allow"


def test_gateway_priority_deny_wildcard_wins_is_denied():
    # tool:mcp/slack：第 2 行 deny 通配按序先于第 3 行 allow 通配 -> DENIED，
    # 且归因必须落在第 2 行。
    out = _explain(GATEWAY_MODEL, GATEWAY_POLICY, "claude-code", "tool:mcp/slack", "use")
    assert out["allowed"] is False
    assert out["winning_rules"] and out["winning_rules"][0]["line"] == 2
    assert out["winning_rules"][0]["eft"] == "deny"
    assert "Line 2" in out["advice"] and "DENIED" in out["advice"]


def test_gateway_keymatch_pattern_is_not_literal():
    # 关键回归：'tool:mcp/*' 必须按 keyMatch 前缀语义匹配，
    # 不能当字面量（修复前所有通配规则都"不相关"）。
    out = _explain(GATEWAY_MODEL, GATEWAY_POLICY, "claude-code", "tool:websearch", "use")
    rules = " ".join(r["rule"] for r in out["matching_rules"])
    assert "tool:*" in rules, out["matching_rules"]
    assert out["allowed"] is True


def test_gateway_unrelated_subject_reports_near_miss_with_g_hint():
    # 无关 subject 命中 model:* 通配、只在 sub 位置失败：DENIED，
    # near-miss 精确归因到 sub，并提示补 g 赋值（比笼统的"没有相关规则"更有用）。
    out = _explain(GATEWAY_MODEL, GATEWAY_POLICY, "other-agent", "model:deepseek", "use")
    assert out["allowed"] is False
    assert out["winning_rules"] == []
    assert any("sub mismatch" in w for f in out["near_misses"] for w in f["why_not"]), out["near_misses"]
    assert "g assignment" in out["advice"]


def test_gateway_keymatch_near_miss_note_names_the_pattern():
    # near-miss 归因要写清是 keyMatch 模式不匹配，而不是笼统的字符串不等。
    out = _explain(GATEWAY_MODEL, GATEWAY_POLICY, "claude-code", "tool:mcp/slack", "use")
    notes = " ".join(w for f in out["near_misses"] for w in f["why_not"])
    assert "keyMatch pattern" in notes, out["near_misses"]


def test_deny_override_effect_blocks_when_any_deny_matches():
    model_conf = GATEWAY_MODEL.replace(
        "e = priority(p.eft) || deny",
        "e = !some(where (p.eft == deny))",
    )
    out = _explain(model_conf, GATEWAY_POLICY, "claude-code", "tool:mcp/slack", "use")
    assert out["allowed"] is False  # line 2 deny matched -> deny-override wins

    # 只有 allow 命中时放行
    policy = "p, claude-code, tool:web*, use, allow\np, claude-code, tool:mcp/*, use, deny\n"
    out = _explain(model_conf, policy, "claude-code", "tool:websearch", "use")
    assert out["allowed"] is True


def test_default_effect_with_eft_column_ignores_deny_lines():
    # 默认效果 some(where (p.eft == allow))：deny 行存在但只要也有 allow 命中就放行
    model_conf = GATEWAY_MODEL.replace("e = priority(p.eft) || deny",
                                       "e = some(where (p.eft == allow))")
    out = _explain(model_conf, GATEWAY_POLICY, "claude-code", "tool:mcp/slack", "use")
    assert out["allowed"] is True
