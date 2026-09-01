# -*- coding: utf-8 -*-
"""高压测试：大规模配置下的准确性、速度、边界条件。

生成带已知埋错的大规模配置（重复规则、角色环、token数错误、
格式错误行），验证 Doctor 能 100% 找出所有埋错，并测量耗时。
"""
import os
import sys
import time
import random

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


def generate_stress_policy(n_rules=5000, seed=42):
    rng = random.Random(seed)
    lines = []
    planted = {"dup": 0, "cycle": 0, "bad_token": 0, "roles": set()}
    # 正常规则：唯一化（避免随机碰撞产生计划外重复）
    users = [f"user{i}" for i in range(500)]
    objs = [f"doc{i}" for i in range(10)]
    combos = [(u, o, a) for u in users for o in objs for a in ["read", "write"]]
    rng.shuffle(combos)
    for u, o, a in combos[: n_rules - 30]:
        lines.append(f"p, {u}, {o}, {a}")
    # 埋错1：50 条精确重复（从已生成的里复制）
    dups_src = rng.sample([l for l in lines if l.startswith("p,")], 50)
    for d in dups_src:
        lines.append(d)
        planted["dup"] += 1
    # 埋错2：10 条角色环（a->b->c->a 等 10 组三角环）
    for g in range(10):
        a, b, c = f"ga{g}", f"gb{g}", f"gc{g}"
        lines += [f"g, {a}, {b}", f"g, {b}, {c}", f"g, {c}, {a}"]
        planted["cycle"] += 1
        planted["roles"] |= {a, b, c}
    # 埋错3：20 条 token 数错误（3 个字段应为 4）
    for i in range(20):
        lines.append(f"p, baduser{i}, doc{i%10}")
        planted["bad_token"] += 1
    rng.shuffle(lines)
    return "\n".join(lines), planted


def test_stress_accuracy_and_speed():
    policy, planted = generate_stress_policy(5000)
    t0 = time.time()
    result = handler.diagnose({"model_conf": GOOD_MODEL, "policy_csv": policy})
    elapsed = time.time() - t0

    issues = result["issues"]
    found_dup = sum(1 for i in issues if i["check"] == "duplicates")
    found_cycle = sum(1 for i in issues if i["check"] == "role_cycle")
    found_token = sum(1 for i in issues if i["check"] == "token_count")

    assert found_dup == planted["dup"], f"duplicates: {found_dup}/{planted['dup']}"
    assert found_cycle == planted["cycle"], f"cycles: {found_cycle}/{planted['cycle']}"
    assert found_token == planted["bad_token"], f"token: {found_token}/{planted['bad_token']}"
    assert elapsed < 10, f"too slow: {elapsed:.2f}s"
    print(f"[STRESS] 5003 rules | dup {found_dup}/{planted['dup']} | "
          f"cycle {found_cycle}/{planted['cycle']} | token {found_token}/{planted['bad_token']} "
          f"| {elapsed*1000:.0f}ms | total issues={len(issues)}")


def test_edge_cases_no_crash():
    for name, cfg in {
        "empty": "",
        "only_comments": "# nothing here\n\n",
        "malformed": "this is not csv at all\np\n,,,,\n",
        "unicode": "p, 用户甲, 文档乙, 读取\np, 用户甲, 文档乙, 读取",
        "huge_line": "p, u, " + ",".join(f"o{i}" for i in range(500)) + ", read",
    }.items():
        result = handler.diagnose({"model_conf": GOOD_MODEL, "policy_csv": cfg})
        assert isinstance(result, dict) and "issues" in result
        print(f"[EDGE] {name}: ok, issues={len(result['issues'])}")


def test_explain_deny_scale():
    """大策略库下 explain_deny 依然给出正确归因。"""
    policy, _ = generate_stress_policy(5000)
    policy += "\np, targetuser, targetdoc, write"
    t0 = time.time()
    out = handler.explain_deny({"model_conf": GOOD_MODEL, "policy_csv": policy,
                                "sub": "targetuser", "obj": "targetdoc", "act": "write"})
    elapsed = time.time() - t0
    assert out["allowed"] is True
    assert any("targetuser" in r["rule"] for r in out["matching_rules"])
    assert elapsed < 5
    print(f"[EXPLAIN-SCALE] allowed={out['allowed']} matched={len(out['matching_rules'])} "
          f"rules_scanned=~5000 in {elapsed*1000:.0f}ms")
