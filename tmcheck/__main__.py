"""Command line: python -m tmcheck MODEL.yaml

Print one JSON object with the keys "issues", "gaps", "policy" and "ranked" (each a list of
objects with the dataclass fields, for example {"ref": "f01", "category": "T"}).
Exit code 2 if the file cannot be loaded, 1 if there are any issues, gaps or policy findings,
otherwise 0. If there are structural issues you may leave "gaps" and "policy" empty.
"""
from __future__ import annotations

import sys
import json
from dataclasses import asdict

from tmcheck.core import (
    load_model,
    validate,
    coverage_gaps,
    policy_findings,
    rank,
    ModelError,
)


def main(argv=None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if len(argv) != 1:
        print("usage: python -m tmcheck MODEL.yaml", file=sys.stderr)
        return 2
    path = argv[0]

    try:
        model = load_model(path)
    except ModelError:
        return 2
    except Exception:
        return 2

    issues = validate(model)

    if issues:
        gaps = []
        policy = []
    else:
        gaps = coverage_gaps(model)
        policy = policy_findings(model)

    ranked = rank(model)

    output = {
        "issues": [asdict(i) for i in issues],
        "gaps": [asdict(g) for g in gaps],
        "policy": [asdict(p) for p in policy],
        "ranked": [asdict(r) for r in ranked],
    }

    print(json.dumps(output, indent=2))

    if issues or gaps or policy:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())