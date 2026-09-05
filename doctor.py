#!/usr/bin/env python3
"""Casbin Config Doctor - standalone command line entry point.

Zero dependencies (stdlib only). Works without RailCall:

    python doctor.py diagnose      --model model.conf --policy policy.csv
    python doctor.py explain-deny  --model model.conf --policy policy.csv \
                                   --sub alice --obj data1 --act read
    python doctor.py generate      --requirement "RBAC where admins manage everything"

Every command also accepts --json for machine-readable output.
`diagnose` exits with status 1 when errors are found, so it can gate CI.
"""

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from handlers import handler  # noqa: E402

COMMANDS = (
    "diagnose",
    "explain-deny",
    "validate-model",
    "check-policy",
    "detect-duplicates",
    "detect-role-cycle",
    "generate",
    "compare",
    "lint",
)


def read(path):
    with open(path, "r", encoding="utf-8") as fh:
        return fh.read()


def dump(payload):
    print(json.dumps(payload, indent=2, ensure_ascii=False))


def print_diagnose(result):
    print(result["summary"])
    if not result["issues"]:
        print("Configuration looks healthy.")
        return
    for issue in result["issues"]:
        location = "line %s" % issue["line"] if issue.get("line") else "-"
        print("  [%s] %s (%s) %s" % (
            issue.get("severity", "info").upper(),
            location,
            issue.get("check", "-"),
            issue["message"],
        ))


def print_explain(result):
    verdict = "ALLOWED" if result["allowed"] else "DENIED"
    print("verdict: %s" % verdict)
    print("request: %s" % json.dumps(result["request"], ensure_ascii=False))
    print("roles considered: %s" % ", ".join(result["roles_considered"]))
    if result["matching_rules"]:
        print("matching rules:")
        for rule in result["matching_rules"]:
            print("  line %s: %s" % (rule["line"], rule["rule"]))
    if result["near_misses"]:
        print("near misses (closest rules that did not match):")
        for miss in result["near_misses"]:
            print("  line %s: %s" % (miss["line"], miss["rule"]))
            for reason in miss["why_not"]:
                print("      - %s" % reason)
    if result.get("matcher"):
        print("matcher: %s" % result["matcher"])
    print("advice: %s" % result["advice"])


def build_parser():
    parser = argparse.ArgumentParser(
        prog="doctor.py",
        description="Diagnose, generate and fix Casbin model.conf / policy.csv configurations.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("diagnose", help="full configuration check-up")
    p.add_argument("--model", required=True, help="path to model.conf")
    p.add_argument("--policy", required=True, help="path to policy.csv")
    p.add_argument("--json", action="store_true", help="emit raw JSON")

    p = sub.add_parser("explain-deny", help="explain why enforce() returns false")
    p.add_argument("--model", required=True, help="path to model.conf")
    p.add_argument("--policy", required=True, help="path to policy.csv")
    p.add_argument("--sub", required=True, help="request subject, e.g. alice")
    p.add_argument("--obj", required=True, help="request object, e.g. data1")
    p.add_argument("--act", required=True, help="request action, e.g. read")
    p.add_argument("--dom", default=None, help="tenant/domain, for multi-tenant (domains) models")
    p.add_argument("--json", action="store_true", help="emit raw JSON")

    p = sub.add_parser("validate-model", help="check model.conf structure")
    p.add_argument("--model", required=True, help="path to model.conf")
    p.add_argument("--json", action="store_true", help="emit raw JSON")

    p = sub.add_parser("check-policy", help="check one policy line's token count")
    p.add_argument("--model", required=True, help="path to model.conf")
    p.add_argument("--line", required=True, help="policy line, e.g. 'p, alice, data1, read'")
    p.add_argument("--json", action="store_true", help="emit raw JSON")

    p = sub.add_parser("detect-duplicates", help="find duplicate policy rules")
    p.add_argument("--policy", required=True, help="path to policy.csv")
    p.add_argument("--json", action="store_true", help="emit raw JSON")

    p = sub.add_parser("detect-role-cycle", help="find role inheritance cycles")
    p.add_argument("--policy", required=True, help="path to policy.csv")
    p.add_argument("--json", action="store_true", help="emit raw JSON")

    p = sub.add_parser("generate", help="generate config from plain language")
    p.add_argument("--requirement", required=True, help="plain-language requirement")
    p.add_argument("--json", action="store_true", help="emit raw JSON")

    p = sub.add_parser("compare", help="diff two policy files")
    p.add_argument("--policy-a", required=True, help="path to the old policy.csv")
    p.add_argument("--policy-b", required=True, help="path to the new policy.csv")
    p.add_argument("--json", action="store_true", help="emit raw JSON")

    p = sub.add_parser("lint", help="policy reference-integrity lint (orphan/dead-assignment/domain)")
    p.add_argument("--model", required=True, help="path to model.conf")
    p.add_argument("--policy", required=True, help="path to policy.csv")
    p.add_argument("--json", action="store_true", help="emit raw JSON")

    return parser


def run(args):
    if args.command == "diagnose":
        result = handler.diagnose({
            "model_conf": read(args.model),
            "policy_csv": read(args.policy),
        })
        if args.json:
            dump(result)
        else:
            print_diagnose(result)
        return 0 if result["healthy"] else 1

    if args.command == "explain-deny":
        result = handler.explain_deny({
            "model_conf": read(args.model),
            "policy_csv": read(args.policy),
            "sub": args.sub,
            "obj": args.obj,
            "act": args.act,
            "dom": args.dom,
        })
        if args.json:
            dump(result)
        else:
            print_explain(result)
        return 0 if result["allowed"] else 1

    if args.command == "validate-model":
        result = handler.validate_model({"model_conf": read(args.model)})
        if args.json:
            dump(result)
        else:
            print(result["summary"])
            for issue in result["issues"]:
                print("  [%s] %s" % (issue["severity"].upper(), issue["message"]))
        return 0 if result["valid"] else 1

    if args.command == "check-policy":
        result = handler.check_policy({
            "model_conf": read(args.model),
            "policy_line": args.line,
        })
        dump(result) if args.json else print(json.dumps(result, ensure_ascii=False))
        return 0 if result["ok"] else 1

    if args.command == "detect-duplicates":
        result = handler.detect_duplicates({"policy_csv": read(args.policy)})
        dump(result)
        return 0 if not result["duplicates"] else 1

    if args.command == "detect-role-cycle":
        result = handler.detect_role_cycle({"policy_csv": read(args.policy)})
        dump(result)
        return 0 if not result["cycles"] else 1

    if args.command == "generate":
        result = handler.generate({"requirement": args.requirement})
        if args.json or result.get("matched") is None:
            dump(result)
        else:
            print("# template: %s" % result["matched"])
            print("# --- model.conf ---")
            print(result["model_conf"])
            print("# --- policy.csv ---")
            print(result["policy_csv"])
        return 0

    if args.command == "compare":
        result = handler.compare({
            "policy_a": read(args.policy_a),
            "policy_b": read(args.policy_b),
        })
        dump(result)
        return 0

    if args.command == "lint":
        result = handler.lint_policy({
            "model_conf": read(args.model),
            "policy_csv": read(args.policy),
        })
        if args.json:
            dump(result)
        else:
            print(result["summary"])
            for f in result["findings"]:
                location = "line %s" % f["line"] if f.get("line") else "-"
                print("  [%s] %s (%s) %s" % (
                    f.get("severity", "info").upper(), location,
                    f.get("check", "-"), f["message"]))
        return 0 if result["healthy"] else 1

    return 1


def main(argv=None):
    args = build_parser().parse_args(argv)
    try:
        return run(args)
    except FileNotFoundError as exc:
        print("error: file not found: %s" % exc.filename, file=sys.stderr)
        return 2
    except UnicodeDecodeError as exc:
        print("error: file is not valid UTF-8 text (%s)" % exc.reason, file=sys.stderr)
        return 2
    except KeyError as exc:
        print("error: missing required input field %s" % exc, file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
