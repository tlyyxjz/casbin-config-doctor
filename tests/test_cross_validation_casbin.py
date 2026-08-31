"""Cross-validation against the real casbin library (dev-side only).

The module itself is stdlib-only; this test is skipped when casbin is not
installed. It proves explain_deny() verdicts agree with casbin's own
enforce() on the official example configs.
"""
import os
import sys

import pytest

casbin = pytest.importorskip("casbin", reason="optional dev dependency")

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "handlers"))
import handler  # noqa: E402

REAL = os.path.join(os.path.dirname(__file__), "real_data")

CASES = [
    ("rbac_model.conf", "rbac_policy.csv", "alice", "data1", "read"),
    ("rbac_model.conf", "rbac_policy.csv", "alice", "data2", "read"),
    ("rbac_model.conf", "rbac_policy.csv", "alice", "data1", "write"),
    ("basic_model.conf", "basic_policy.csv", "alice", "data1", "read"),
    ("basic_model.conf", "basic_policy.csv", "bob", "data2", "write"),
]


@pytest.mark.parametrize("model,policy,sub,obj,act", CASES)
def test_doctor_matches_real_casbin(model, policy, sub, obj, act):
    real = bool(casbin.Enforcer(
        os.path.join(REAL, model), os.path.join(REAL, policy)
    ).enforce(sub, obj, act))
    mine = handler.explain_deny({
        "model_conf": open(os.path.join(REAL, model), encoding="utf-8").read(),
        "policy_csv": open(os.path.join(REAL, policy), encoding="utf-8").read(),
        "sub": sub, "obj": obj, "act": act,
    })
    assert bool(mine["allowed"]) is real, (
        f"MISMATCH for {sub}/{obj}/{act}: casbin={real} doctor={mine['allowed']}"
    )
