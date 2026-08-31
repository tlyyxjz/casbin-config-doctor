"""Smoke test against REAL Casbin example configs (casbin/casbin/examples).

These are the actual config files used by the casbin library's own test suite.
Assert: every official example model validates clean, and diagnose() reports
healthy on every official policy file.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "handlers"))
import handler  # noqa: E402

REAL = os.path.join(os.path.dirname(__file__), "real_data")


def _read(name):
    with open(os.path.join(REAL, name), encoding="utf-8") as f:
        return f.read()


def test_real_rbac_model_validates():
    out = handler.validate_model({"model_conf": _read("rbac_model.conf")})
    assert out["valid"] is True, out


def test_real_rbac_policy_diagnoses_healthy():
    out = handler.diagnose({"model_conf": _read("rbac_model.conf"),
                            "policy_csv": _read("rbac_policy.csv")})
    errors = [i for i in out["issues"] if i["severity"] == "error"]
    assert errors == [], errors


def test_real_rbac_domains_model_validates():
    out = handler.validate_model({"model_conf": _read("rbac_with_domains_model.conf")})
    assert out["valid"] is True, out


def test_real_basic_model_validates():
    out = handler.validate_model({"model_conf": _read("basic_model.conf")})
    assert out["valid"] is True, out


def test_real_keymatch_model_validates():
    out = handler.validate_model({"model_conf": _read("keymatch_model.conf")})
    assert out["valid"] is True, out


def test_real_keymatch_policy_diagnoses_healthy():
    out = handler.diagnose({"model_conf": _read("keymatch_model.conf"),
                            "policy_csv": _read("keymatch_policy.csv")})
    errors = [i for i in out["issues"] if i["severity"] == "error"]
    assert errors == [], errors


def test_real_rbac_enforce_explain_allow():
    # casbin官方示例: alice 继承 admin? 实际 rbac_policy: g, alice, admin
    # data2 仅 admin:write... 检查 read: p, admin, data1, read -> alice 读 data1 应允许
    out = handler.explain_deny({"model_conf": _read("rbac_model.conf"),
                                "policy_csv": _read("rbac_policy.csv"),
                                "sub": "alice", "obj": "data1", "act": "read"})
    assert out["allowed"] is True, out


def test_real_abac_model_parses():
    out = handler.validate_model({"model_conf": _read("abac_model.conf")})
    assert out["valid"] is True, out
