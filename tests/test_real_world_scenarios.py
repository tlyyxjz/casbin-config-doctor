# -*- coding: utf-8 -*-
"""真实使用场景实测：复现真实项目里最常见的 casbin 配置错误，
验证 Doctor 是否能检出并给出有效归因。发现检不出的 = Doctor v0.2 升级清单。"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "handlers"))
import handler  # noqa: E402

# 场景1：RBAC 角色赋了但 enforce 还是 false（真实项目最高频）
# 原因：用户以为加了 g 规则就行，但 policy 里写的是用户名不是角色名
SC1_MODEL = """[request_definition]
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
SC1_POLICY = """p, admin, /api/users, GET
p, admin, /api/users, POST
g, zhangsan, admin
"""


def test_s1_rbac_role_assignment():
    """张三有 admin 角色，查 /api/users GET → 应允许"""
    out = handler.explain_deny({"model_conf": SC1_MODEL, "policy_csv": SC1_POLICY,
                                "sub": "zhangsan", "obj": "/api/users", "act": "GET"})
    assert out["allowed"] is True, out
    assert "admin" in out["roles_considered"]


def test_s1_rbac_typo_catch():
    """g 规则里角色名打错（amin 而不是 admin）→ Doctor 应指出角色没展开"""
    bad = SC1_POLICY.replace("g, zhangsan, admin", "g, zhangsan, amin")
    out = handler.explain_deny({"model_conf": SC1_MODEL, "policy_csv": bad,
                                "sub": "zhangsan", "obj": "/api/users", "act": "GET"})
    assert out["allowed"] is False
    # 归因：near_miss 或 roles_considered 应能看出 zhangsan 没有可用角色
    assert out["near_misses"] or out["advice"], out


# 场景2：多行/注释/空格/CRLF 的真实 model.conf（真实项目的文件都很脏）
SC2_MODEL = """# 后台权限模型
[request_definition]
r = sub, obj, act   # 请求三元组

[policy_definition]
p = sub, obj, act

[role_definition]
g = _, _

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = g(r.sub, p.sub) && r.obj == p.obj && r.act == p.act
"""


def test_s2_dirty_model_config():
    """带注释和行内注释的 model.conf 应能正常解析"""
    out = handler.validate_model({"model_conf": SC2_MODEL})
    assert out["valid"] is True, out


# 场景3：keyMatch2 + regexMatch（真实项目最常用的路径匹配）
SC3_MODEL = """[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act

[role_definition]
g = _, _

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = g(r.sub, p.sub) && keyMatch2(r.obj, p.obj) && regexMatch(r.act, p.act)
"""
SC3_POLICY = """p, admin, /api/*, (GET)|(POST)
p, user, /api/profile.*, GET

g, alice, admin
g, bob, user
"""


def test_s3_keymatch_policy_diagnose():
    out = handler.diagnose({"model_conf": SC3_MODEL, "policy_csv": SC3_POLICY})
    errors = [i for i in out["issues"] if i["severity"] == "error"]
    assert errors == [], errors


# 场景4：多租户 domains（真实项目第二大高频场景）
SC4_MODEL = """[request_definition]
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
SC4_POLICY = """p, admin, domain1, data1, read
p, admin, domain1, data1, write
g, alice, admin, domain1
"""


def test_s4_domains_explain():
    """多租户：alice 在 domain1 有 admin 角色 → data1 read 应允许"""
    out = handler.explain_deny({"model_conf": SC4_MODEL, "policy_csv": SC4_POLICY,
                                "sub": "alice", "dom": "domain1", "obj": "data1", "act": "read"})
    # 当前 Doctor 未处理 domains 三元 g 规则 —— 预期这里是已知缺口
    print(f"\n[domains] allowed={out['allowed']} roles={out['roles_considered']}")
    # v0.2 目标：允许且 roles_considered 含 admin


# 场景5：ABAC 属性匹配（r.obj.owner）
SC5_MODEL = """[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = r.sub == r.obj.owner && r.act == p.act
"""


def test_s5_abac_model_validates():
    out = handler.validate_model({"model_conf": SC5_MODEL})
    # r.obj.owner 中 obj 不是策略定义的变量，validate 不应误报；r.sub==p.act 引用要能对上
    print(f"\n[abac] valid={out['valid']} issues={out['issues']}")


def test_s6_gorm_adapter_real_table():
    """真实 gorm-adapter 的 casbin_rule 表导出格式（ptyp/v0-v5 列）"""
    policy = "p,p,admin,/api/users,GET\np,p,admin,/api/users,POST\ng,p,zhangsan,admin\n"
    out = handler.detect_duplicates({"policy_csv": policy})
    assert out["duplicates"] == []
