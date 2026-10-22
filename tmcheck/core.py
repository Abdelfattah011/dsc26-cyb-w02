"""tmcheck: a checker for threat models kept as YAML in the repository.

Fill in every function. Keep the names and signatures exactly as they are: the grader imports them.
The full rules are in README.md ("What to build").
"""
from __future__ import annotations

from dataclasses import dataclass
import yaml
import re


class ModelError(Exception):
    """The file cannot be read as a threat model."""


@dataclass(frozen=True, order=True)
class Issue:
    ref: str            # id of the zone/element/flow/threat the issue is about
    code: str
    message: str = ""


@dataclass(frozen=True, order=True)
class Gap:
    ref: str            # element or flow id
    category: str       # one STRIDE letter


@dataclass(frozen=True)
class RankedThreat:
    id: str
    score: int
    level: str          # "high" | "medium" | "low"


def load_model(path) -> dict:
    """Read the YAML file with yaml.safe_load and return the mapping.

    Missing or null `zones`, `elements`, `flows`, `threats` become []. Raise ModelError if the
    file cannot be read, is not valid YAML, uses a tag safe_load refuses, has a top level that
    is not a mapping, or has one of the four sections that is not a list.
    """
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
    except Exception as e:
        raise ModelError(f"Cannot read file or invalid YAML: {e}")

    if data is None:
        data = {}

    if not isinstance(data, dict):
        raise ModelError("Top level is not a mapping")

    sections = ["zones", "elements", "flows", "threats"]
    for sec in sections:
        if sec not in data or data[sec] is None:
            data[sec] = []
        if not isinstance(data[sec], list):
            raise ModelError(f"Section '{sec}' is not a list")

    return data


def applicable(kind: str, *, is_log: bool = False) -> set[str]:
    """STRIDE per element: the categories that apply to `kind`. Unknown kind: ValueError."""
    if kind == "external_entity":
        return {"S", "R"}
    elif kind == "process":
        return {"S", "T", "R", "I", "D", "E"}
    elif kind == "data_store":
        res = {"T", "I", "D"}
        if is_log:
            res.add("R")
        return res
    elif kind == "data_flow":
        return {"T", "I", "D"}
    else:
        raise ValueError(f"Unknown kind: {kind}")


def validate(model: dict) -> list[Issue]:
    """Structural problems, sorted by (ref, code, message), no duplicates."""
    issues = set()

    zones = model.get("zones", [])
    elements = model.get("elements", [])
    flows = model.get("flows", [])
    threats = model.get("threats", [])

    # Unified ID space check for DUPLICATE_ID across all sections
    seen_ids = set()
    duplicate_ids = set()

    all_sections = [("zones", zones), ("elements", elements), ("flows", flows), ("threats", threats)]
    for _, items in all_sections:
        if isinstance(items, list):
            for item in items:
                if isinstance(item, dict):
                    item_id = item.get("id")
                    if item_id:
                        if item_id in seen_ids:
                            duplicate_ids.add(item_id)
                        else:
                            seen_ids.add(item_id)

    for dup_id in duplicate_ids:
        issues.add(Issue(ref=dup_id, code="DUPLICATE_ID"))

    # Map existing valid entities for references
    zone_ids = {z.get("id") for z in zones if isinstance(z, dict) and z.get("id")}
    element_ids = {e.get("id") for e in elements if isinstance(e, dict) and e.get("id")}
    element_kinds = {e.get("id"): e.get("kind") for e in elements if isinstance(e, dict) and e.get("id")}
    element_is_log = {e.get("id"): e.get("is_log", False) for e in elements if isinstance(e, dict) and e.get("id")}
    flow_ids = {f.get("id") for f in flows if isinstance(f, dict) and f.get("id")}

    # Validate elements
    for e in elements:
        if not isinstance(e, dict):
            continue
        eid = e.get("id")
        kind = e.get("kind")
        zone = e.get("zone")

        if kind not in {"external_entity", "process", "data_store"}:
            if eid:
                issues.add(Issue(ref=eid, code="BAD_KIND"))

        if zone and zone not in zone_ids:
            if eid:
                issues.add(Issue(ref=eid, code="UNKNOWN_ZONE"))

    # Validate flows
    for f in flows:
        if not isinstance(f, dict):
            continue
        fid = f.get("id")
        source = f.get("source")
        target = f.get("target")

        if source not in element_ids or target not in element_ids:
            if fid:
                issues.add(Issue(ref=fid, code="UNKNOWN_REF"))
        else:
            if source == target:
                issues.add(Issue(ref=fid, code="INVALID_FLOW"))
            else:
                src_kind = element_kinds.get(source)
                tgt_kind = element_kinds.get(target)
                if src_kind != "process" and tgt_kind != "process":
                    issues.add(Issue(ref=fid, code="INVALID_FLOW"))

    # Validate threats
    valid_categories = set("STRIDE")
    for t in threats:
        if not isinstance(t, dict):
            continue
        tid = t.get("id")
        target = t.get("target")
        category = t.get("category")
        likelihood = t.get("likelihood")
        impact = t.get("impact")
        status = t.get("status")
        mitigation = t.get("mitigation")
        justification = t.get("justification")

        if target not in element_ids and target not in flow_ids:
            if tid:
                issues.add(Issue(ref=tid, code="UNKNOWN_REF"))

        if not isinstance(category, str) or category not in valid_categories:
            if tid:
                issues.add(Issue(ref=tid, code="BAD_CATEGORY"))
        else:
            if target in element_ids:
                kind = element_kinds.get(target)
                is_l = element_is_log.get(target, False)
                try:
                    app = applicable(kind, is_log=is_l)
                    if category not in app:
                        issues.add(Issue(ref=tid, code="INAPPLICABLE_CATEGORY"))
                except ValueError:
                    pass
            elif target in flow_ids:
                if category not in {"T", "I", "D"}:
                    issues.add(Issue(ref=tid, code="INAPPLICABLE_CATEGORY"))

        if not isinstance(likelihood, int) or isinstance(likelihood, bool) or not (1 <= likelihood <= 5) or \
           not isinstance(impact, int) or isinstance(impact, bool) or not (1 <= impact <= 5):
            if tid:
                issues.add(Issue(ref=tid, code="BAD_SCORE"))

        if status not in {"open", "mitigated", "accepted"}:
            if tid:
                issues.add(Issue(ref=tid, code="BAD_STATUS"))

        if status == "mitigated":
            if not isinstance(mitigation, str) or not mitigation.strip():
                if tid:
                    issues.add(Issue(ref=tid, code="MISSING_MITIGATION"))

        if status == "accepted":
            if not isinstance(justification, str) or not justification.strip():
                if tid:
                    issues.add(Issue(ref=tid, code="MISSING_JUSTIFICATION"))

    return sorted(list(issues))


def crossing_flows(model: dict) -> list[str]:
    """Ids of flows whose source and target are in different zones, in file order."""
    elements = {e["id"]: e.get("zone") for e in model.get("elements", []) if isinstance(e, dict) and "id" in e}
    result = []
    for f in model.get("flows", []):
        if not isinstance(f, dict):
            continue
        fid = f.get("id")
        src = f.get("source")
        tgt = f.get("target")
        if fid and src in elements and tgt in elements:
            if elements[src] != elements[tgt]:
                result.append(fid)
    return result


def coverage_gaps(model: dict) -> list[Gap]:
    """(ref, category) pairs in scope with no threat recorded, sorted by ref then S, T, R, I, D, E."""
    elements = {e["id"]: e for e in model.get("elements", []) if isinstance(e, dict) and "id" in e}
    cross_flows = set(crossing_flows(model))

    in_scope_items = set()
    for f in model.get("flows", []):
        if not isinstance(f, dict):
            continue
        fid = f.get("id")
        if fid in cross_flows:
            in_scope_items.add(fid)
            if f.get("source"):
                in_scope_items.add(f.get("source"))
            if f.get("target"):
                in_scope_items.add(f.get("target"))

    threat_map = {}
    for t in model.get("threats", []):
        if not isinstance(t, dict):
            continue
        target = t.get("target")
        cat = t.get("category")
        if target and cat:
            threat_map.setdefault(target, set()).add(cat)

    stride_order = ["S", "T", "R", "I", "D", "E"]

    all_items_order = []
    for e in model.get("elements", []):
        if isinstance(e, dict) and e.get("id") in in_scope_items:
            all_items_order.append((e["id"], "element"))
    for f in model.get("flows", []):
        if isinstance(f, dict) and f.get("id") in in_scope_items:
            all_items_order.append((f["id"], "flow"))

    gaps = []
    for ref, itype in all_items_order:
        if itype == "element":
            e = elements[ref]
            kind = e.get("kind")
            is_l = e.get("is_log", False)
            try:
                app = applicable(kind, is_log=is_l)
            except ValueError:
                app = set()
        else:
            app = {"T", "I", "D"}

        existing_cats = threat_map.get(ref, set())
        for cat in stride_order:
            if cat in app and cat not in existing_cats:
                gaps.append(Gap(ref=ref, category=cat))

    return gaps


def policy_findings(model: dict) -> list[Issue]:
    """UNENCRYPTED_CROSSING, UNAUTHENTICATED_INBOUND, PII_STORE_WITHOUT_I_THREAT, sorted by (ref, code)."""
    issues = set()
    cross_flows = set(crossing_flows(model))

    element_zones = {e["id"]: e.get("zone") for e in model.get("elements", []) if isinstance(e, dict) and "id" in e}
    zone_trust = {z["id"]: z.get("trust", 0) for z in model.get("zones", []) if isinstance(z, dict) and "id" in z}

    safe_protocols = {"https", "tls", "mtls", "sftp", "ssh"}
    for f in model.get("flows", []):
        if not isinstance(f, dict):
            continue
        fid = f.get("id")
        if fid in cross_flows:
            proto = str(f.get("protocol", "")).lower()
            if proto not in safe_protocols:
                issues.add(Issue(ref=fid, code="UNENCRYPTED_CROSSING"))

            src = f.get("source")
            tgt = f.get("target")
            src_zone = element_zones.get(src)
            tgt_zone = element_zones.get(tgt)
            src_trust = zone_trust.get(src_zone, 0)
            tgt_trust = zone_trust.get(tgt_zone, 0)

            if tgt_trust > src_trust:
                if not f.get("authenticated", False):
                    issues.add(Issue(ref=fid, code="UNAUTHENTICATED_INBOUND"))

    threat_map = {}
    for t in model.get("threats", []):
        if not isinstance(t, dict):
            continue
        target = t.get("target")
        cat = t.get("category")
        if target and cat:
            threat_map.setdefault(target, set()).add(cat)

    for e in model.get("elements", []):
        if isinstance(e, dict) and e.get("kind") == "data_store" and e.get("holds_pii", False):
            eid = e.get("id")
            if eid:
                cats = threat_map.get(eid, set())
                if "I" not in cats:
                    issues.add(Issue(ref=eid, code="PII_STORE_WITHOUT_I_THREAT"))

    return sorted(list(issues))


def rank(model: dict) -> list[RankedThreat]:
    """Open threats with valid scores, by score desc, then impact desc, then natural id order."""
    ranked = []
    for t in model.get("threats", []):
        if not isinstance(t, dict):
            continue
        if t.get("status") == "open":
            likelihood = t.get("likelihood")
            impact = t.get("impact")
            if isinstance(likelihood, int) and not isinstance(likelihood, bool) and 1 <= likelihood <= 5 and \
               isinstance(impact, int) and not isinstance(impact, bool) and 1 <= impact <= 5:
                score = likelihood * impact
                if score >= 15:
                    level = "high"
                elif score >= 8:
                    level = "medium"
                else:
                    level = "low"
                ranked.append({
                    "id": t.get("id"),
                    "score": score,
                    "impact": impact,
                    "level": level
                })

    def natural_sort_key(item):
        parts = re.split(r'(\d+)', item["id"])
        return [int(p) if p.isdigit() else p for p in parts]

    ranked.sort(key=lambda x: (-x["score"], -x["impact"], natural_sort_key(x)))

    return [RankedThreat(id=r["id"], score=r["score"], level=r["level"]) for r in ranked]
