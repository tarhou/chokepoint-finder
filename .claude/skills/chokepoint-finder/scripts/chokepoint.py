#!/usr/bin/env python3
"""Chokepoint ranking, in one dependency-free file.

Standard library only, runs anywhere python3 runs:

    python3 chokepoint.py --demo                # see it work, zero input
    python3 chokepoint.py --sample > est.json   # the input schema, by example
    python3 chokepoint.py est.json              # rank your own estate
    python3 chokepoint.py est.json --json       # machine-readable output

Input: a JSON object with "findings" (required) and "assets" (optional).
Run --sample for the exact shape. The math follows the same method as the
chokepoint-finder engine: findings group by the fix they share, then greedy
weighted max-coverage picks the ordered set of actions that eliminates the
most risk, each action valued by what it adds GIVEN everything ranked above
it is already done.

What the ranking guarantees, stated precisely: weighted max-coverage is
NP-hard, and no polynomial algorithm beats a (1 - 1/e) approximation unless
P = NP (Feige, 1998). The classical greedy -- take the highest MARGINAL
covered risk each round -- achieves that bound (Nemhauser, Wolsey and
Fisher, 1978), and it is the default mode here, with one caveat: the early
stop available to library callers (`target_share < 1`) trades the fixed-k
bound for a shorter list. `--top` defines k; it does not weaken the bound.
--effort-weighted divides marginal risk by
sqrt(effort) instead; that is a cost-benefit heuristic, and ratio-greedy
under a cardinality constraint has NO constant-factor guarantee, so it is
opt-in and named honestly rather than sold under a theorem it does not
satisfy.

Coverage is reported as a share of total weighted FINDING risk: disjoint
marginal numerators over one fixed denominator, so the cumulative share can
never exceed 100%. No quantity with a different denominator is ever blended
into that percentage.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import sys
import unicodedata
from collections import defaultdict

SEVERITY_WEIGHT = {"critical": 10.0, "high": 6.0, "medium": 2.5, "low": 1.0, "info": 0.1}
EFFORT = {"patch": 2.0, "image-rebuild": 1.5, "iam-policy": 1.0, "sg-rule": 1.0}
# (field, id prefix, kind, title) -- base_image dominates patch_key (same fix);
# iam_role and security_group group independently, exactly like the engine.
FIX_KEYS = (("base_image", "rebuild", "image-rebuild",
             "Rebuild base image {k} and redeploy dependents"),
            ("patch_key", "patch", "patch", "Roll out {k} fleet-wide"),
            ("iam_role", "iam", "iam-policy", "Restrict IAM role {k}"),
            ("security_group", "sg", "sg-rule", "Close exposed ports on {k}"))
OOB_THRESHOLD = 3  # CTI out-of-band policy: 3 of 5 criteria
BOOLEAN_FIELDS = {"kev", "exploit_available", "crown_jewel", "externally_facing", "gov_tip"}


def safe_identifier(value: object) -> str:
    """Return an opaque control-flow identifier; never echo scanner text."""
    raw = str(value)
    return f"external-{hashlib.sha256(raw.encode()).hexdigest()}"


def safe_label(value: object, limit: int = 180) -> str:
    normalized = unicodedata.normalize("NFKC", str(value))
    without_controls = "".join(
        character
        for character in normalized
        if not unicodedata.category(character).startswith("C")
    )
    return " ".join(without_controls.split())[:limit]


def short_identifier(value: object) -> str:
    """Return a display-only digest prefix; never use it for control flow."""
    text = str(value)
    marker = text.partition("external-")[2]
    return (marker or hashlib.sha256(text.encode()).hexdigest())[:8]


def validate_estate(estate: dict) -> None:
    if not isinstance(estate, dict) or not isinstance(estate.get("findings"), list):
        raise ValueError("estate must be an object with a findings list")
    findings = estate["findings"]
    assets = estate.get("assets", [])
    if not isinstance(assets, list) or any(not isinstance(item, dict) for item in assets):
        raise ValueError("assets must be a list of objects")
    if any(not isinstance(item, dict) for item in findings):
        raise ValueError("findings must contain objects")
    for finding in findings:
        if not finding.get("asset_id"):
            raise ValueError("every finding needs a non-empty asset_id")
        severity = str(finding.get("severity", "")).lower()
        if severity not in SEVERITY_WEIGHT:
            raise ValueError(f"unsupported severity: {severity!r}")
        for field in (
            "patch_key", "base_image", "iam_role", "security_group",
            "remediation_kind", "remediation_fingerprint", "remediation_target",
        ):
            value = finding.get(field)
            if value is not None and (not isinstance(value, str) or not value):
                raise ValueError(f"{field} must be a non-empty string when present")
        remediation_kind = finding.get("remediation_kind")
        if remediation_kind is not None and remediation_kind not in EFFORT:
            raise ValueError(f"unsupported remediation_kind: {remediation_kind!r}")
    finding_ids = [str(item.get("id") or "") for item in findings]
    if any(not value for value in finding_ids) or len(finding_ids) != len(set(finding_ids)):
        raise ValueError("finding IDs must be non-empty and unique")
    asset_ids = [str(item.get("id") or "") for item in assets]
    if any(not value for value in asset_ids) or len(asset_ids) != len(set(asset_ids)):
        raise ValueError("asset IDs must be non-empty and unique")
    for item in [*assets, *findings]:
        for field in BOOLEAN_FIELDS:
            value = item.get(field)
            if value is not None and not isinstance(value, bool):
                raise ValueError(f"{field} must be a boolean when present")
        for field in ("criticality", "epss", "vpr", "cvss", "cti_score"):
            value = item.get(field)
            if value is not None and (
                isinstance(value, bool)
                or not isinstance(value, (int, float))
                or not math.isfinite(value)
            ):
                raise ValueError(f"{field} must be a finite number")
    ranges = {
        "criticality": (0, 10), "epss": (0, 1), "vpr": (0, 10),
        "cvss": (0, 10), "cti_score": (0, 100),
    }
    for item in [*assets, *findings]:
        for field, (low, high) in ranges.items():
            value = item.get(field)
            if value is not None and not low <= value <= high:
                raise ValueError(f"{field} must be between {low} and {high}")


def exploit_multiplier(f: dict) -> float:
    if f.get("kev"):
        return 3.0
    epss = f.get("epss")
    if epss is not None:
        if epss >= 0.5:
            return 2.2
        if epss >= 0.1:
            return 1.6
    if f.get("exploit_available"):
        return 1.4
    if (f.get("vpr") or 0) >= 9.0:
        return 1.3
    return 1.0


def criticality_multiplier(asset: dict | None) -> float:
    if not asset:
        return 1.0
    crit = max(0.0, min(10.0, float(asset.get("criticality", 5.0))))
    return (0.5 + crit / 10.0) * (1.5 if asset.get("crown_jewel") else 1.0)


def risk(f: dict, asset: dict | None) -> float:
    return (SEVERITY_WEIGHT.get(str(f.get("severity", "medium")).lower(), 2.5)
            * exploit_multiplier(f) * criticality_multiplier(asset))


def out_of_band(f: dict, asset: dict | None) -> tuple[bool, str]:
    """An operational CTI out-of-band policy: 3 of 5 criteria met, or a direct
    government/vendor tip, which skips scoring entirely."""
    if f.get("gov_tip"):
        return True, "direct gov/vendor tip"
    met = []
    if (f.get("cvss") or 0) >= 9.5:
        met.append(f"CVSS {f['cvss']}")
    if (f.get("cti_score") or 0) >= 95:
        met.append("CTI score 95+")
    if f.get("kev"):
        met.append("exploited in the wild")
    if asset and asset.get("externally_facing"):
        met.append("externally facing")
    if f.get("exploit_available"):
        met.append("exploit POC exists")
    if len(met) >= OOB_THRESHOLD:
        return True, f"{len(met)}/5: " + ", ".join(met)
    return False, ""


def synthesize(findings: list[dict]) -> list[dict]:
    groups: dict[tuple, list[dict]] = defaultdict(list)
    image, patch, iam, sg = FIX_KEYS
    for f in findings:
        remediation_kind = f.get("remediation_kind")
        fingerprint = f.get("remediation_fingerprint")
        target = f.get("remediation_target")
        if remediation_kind is not None:
            configured = {
                "image-rebuild": (image, target or f.get(image[0])),
                "patch": (patch, target or f.get(patch[0])),
                "iam-policy": (iam, target or f.get(iam[0])),
                "sg-rule": (sg, target or f.get(sg[0])),
            }
            definition, k = configured[remediation_kind]
            if k:
                groups[(definition[1], definition[2], definition[3], fingerprint or k, k)].append(f)
            continue
        if f.get(image[0]):
            k = f[image[0]]
            groups[(image[1], image[2], image[3], fingerprint or k, k)].append(f)
        elif f.get(patch[0]):
            k = target or f[patch[0]]
            groups[(patch[1], patch[2], patch[3], fingerprint or k, k)].append(f)
        if f.get(iam[0]):
            k = target or f[iam[0]]
            groups[(iam[1], iam[2], iam[3], fingerprint or k, k)].append(f)
        if f.get(sg[0]):
            k = target or f[sg[0]]
            groups[(sg[1], sg[2], sg[3], fingerprint or k, k)].append(f)
    actions = []
    for (prefix, kind, title, fingerprint, k), fs in groups.items():
        action_key = safe_identifier(k)
        if fingerprint != k:
            fingerprint_digest = hashlib.sha256(str(fingerprint).encode()).hexdigest()
            action_key = f"{action_key}::{fingerprint_digest}"
        actions.append({
            "id": f"{prefix}::{action_key}", "kind": kind,
            "title": safe_label(title.format(k=k)),
            "finding_ids": {f["id"] for f in fs},
            "effort": EFFORT.get(kind, 1.0),
            "remediation_fingerprint": str(fingerprint),
            "remediation_target": str(k),
        })
    action_ids = [action["id"] for action in actions]
    if len(action_ids) != len(set(action_ids)):
        raise ValueError("remediation inputs produced duplicate action IDs")
    return actions


def waves(action: dict, findings_by_id: dict, assets: dict) -> dict:
    """Build a site rollout only when a non-crown-jewel canary is provable."""
    by_site: dict[str, set] = defaultdict(set)
    for fid in action["finding_ids"]:
        f = findings_by_id.get(fid)
        if not f:
            continue
        aid = f.get("asset_id")
        name = (assets.get(aid, {}) or {}).get("name", "")
        if not isinstance(name, str):
            name = ""
        prefix = name.split("-", 1)[0] if "-" in name else "unassigned"
        site = prefix if prefix.isalpha() and len(prefix) <= 4 else "unassigned"
        by_site[site].add(aid)

    if not by_site or "unassigned" in by_site:
        return {
            "status": "HOLD",
            "reason": "complete site mapping is required before rollout",
            "waves": [],
        }

    target_records = [assets.get(asset_id, {}) or {}
                      for ids in by_site.values() for asset_id in ids]
    if any("crown_jewel" not in record or "criticality" not in record
           for record in target_records):
        return {
            "status": "HOLD",
            "reason": "explicit crown-jewel and criticality classification is required",
            "waves": [],
        }

    def site_risk(item: tuple[str, set]) -> tuple:
        site, ids = item
        records = [assets.get(asset_id, {}) or {} for asset_id in ids]
        crown_count = sum(1 for record in records if record.get("crown_jewel"))
        criticalities = [float(record.get("criticality", 5.0)) for record in records]
        return (
            crown_count > 0,
            max(criticalities, default=5.0),
            sum(criticalities) / len(criticalities),
            len(ids),
            site,
        )

    eligible = [item for item in by_site.items()
                if all((assets.get(aid, {}) or {}).get("crown_jewel") is False
                       for aid in item[1])]
    if not eligible:
        return {
            "status": "HOLD",
            "reason": "no non-crown-jewel site is eligible as a canary",
            "waves": [],
        }

    canary = min(eligible, key=site_risk)
    remainder = sorted((item for item in by_site.items() if item != canary), key=site_risk)
    ordered = [canary, *remainder]
    return {
        "status": "PRELIMINARY",
        "reason": "lowest-risk eligible non-crown-jewel site selected as canary",
        "waves": [
            {
                "wave": i + 1,
                "assets": len(ids),
                "untrusted_scanner_data": {
                    "site": site,
                    "asset_ids": sorted(ids),
                },
                "role": "canary" if i == 0 else "expand",
            }
            for i, (site, ids) in enumerate(ordered)
        ],
    }


def rank(estate: dict, top: int = 7, target_share: float = 1.0,
         effort_weighted: bool = False) -> dict:
    """Greedy weighted max-coverage over the synthesized actions.

    Default selection is pure marginal covered risk, the classical greedy that
    carries the (1 - 1/e) approximation bound (see module docstring).
    effort_weighted=True divides each marginal by sqrt(effort): a cost-benefit
    heuristic with no approximation guarantee, offered because practitioners
    genuinely want it. Either way the reported shares are marginal finding
    risk over total finding risk -- same unit top and bottom, disjoint
    numerators across picks, so cumulative coverage is bounded by 1.0.
    """
    validate_estate(estate)
    if top < 1:
        raise ValueError("top must be at least 1")
    if not math.isfinite(target_share) or not 0 < target_share <= 1:
        raise ValueError("target_share must be finite and in (0, 1]")
    findings = estate.get("findings", [])
    assets = {a["id"]: a for a in estate.get("assets", [])}
    fbid = {f["id"]: f for f in findings}
    risks = {f["id"]: risk(f, assets.get(f.get("asset_id"))) for f in findings}
    total = sum(risks.values()) or 1.0
    actions = synthesize(findings)

    covered: set[str] = set()
    chosen = []
    cumulative = 0.0
    while actions and len(chosen) < top and cumulative < target_share:
        best, best_score, best_marginal = None, -1.0, 0.0
        for a in sorted(actions, key=lambda x: x["id"]):
            fresh = a["finding_ids"] - covered
            marginal = sum(risks[fid] for fid in fresh)
            score = marginal / (a["effort"] ** 0.5) if effort_weighted else marginal
            if score > best_score:
                best, best_score, best_marginal = a, score, marginal
        if best is None or best_marginal <= 0:
            break
        fresh = best["finding_ids"] - covered
        oob = sum(1 for fid in fresh
                  if out_of_band(fbid[fid], assets.get(fbid[fid].get("asset_id")))[0])
        share = best_marginal / total
        cumulative += share
        touched = {fbid[fid].get("asset_id") for fid in fresh}
        all_targets = {fbid[fid].get("asset_id") for fid in best["finding_ids"]}
        entry = {
            "rank": len(chosen) + 1, "id": best["id"],
            "kind": best["kind"], "findings_retired": len(fresh),
            "assets_touched": len(touched), "share": round(share, 4),
            "cumulative_share": round(cumulative, 4),
            "out_of_band_findings": oob,
            "execution_authorized": False,
            "untrusted_scanner_data": {
                "display_title": best["title"],
                "remediation_target": best["remediation_target"],
                "remediation_fingerprint": best["remediation_fingerprint"],
                "finding_ids": sorted(best["finding_ids"]),
                "target_asset_ids": sorted(all_targets),
                "marginal_finding_ids": sorted(fresh),
                "marginal_target_asset_ids": sorted(touched),
            },
        }
        if best["kind"] == "patch":
            rollout = waves(best, fbid, assets)
            entry["rollout_gate"] = rollout["status"]
            entry["rollout_gate_reason"] = rollout["reason"]
            entry["rollout_waves"] = rollout["waves"]
        chosen.append(entry)
        covered |= best["finding_ids"]
        actions = [a for a in actions if a["id"] != best["id"]]

    return {"artifact_type": "chokepoint_ranking",
            "artifact_version": 1,
            "execution_authorized": False,
            "approval_manifest_hash": None,
            "total_findings": len(findings), "total_assets": len(assets),
            "total_weighted_risk": round(total, 1),
            "risk_eliminated_share": round(cumulative, 4),
            "ranking_mode": "effort_weighted" if effort_weighted else "risk",
            "approximation_guarantee_applies": bool(
                not effort_weighted and target_share == 1.0
            ),
            "chokepoints": chosen}


def to_markdown(result: dict) -> str:
    mode_note = (" Ordered by risk per unit effort: a heuristic with no approximation guarantee."
                 if result.get("ranking_mode") == "effort_weighted" else
                 " Classical (1 - 1/e) cardinality guarantee applies."
                 if result.get("approximation_guarantee_applies") else
                 " Early stopping disables the classical cardinality guarantee.")
    lines = [
        "# Chokepoints",
        "",
        "> Ranking only — not an approval artifact. Execution authorized: NO. "
        "Approval manifest hash: NONE.",
        "",
        f"{len(result['chokepoints'])} actions cover "
        f"{result['risk_eliminated_share']:.0%} of weighted finding risk across "
        f"{result['total_findings']:,} findings / {result['total_assets']:,} assets."
        + mode_note,
        "",
    ]
    for c in result["chokepoints"]:
        data = c["untrusted_scanner_data"]
        title = safe_label(data.get("display_title"), 160) or "Untitled remediation"
        lines.append(f"**#{c['rank']} {title}** `id:{short_identifier(c['id'])}`")
        lines.append(
            f"- retires {c['findings_retired']} findings on {c['assets_touched']} assets "
            f"({c['share']:.0%} of risk, cumulative {c['cumulative_share']:.0%})"
        )
        if c["out_of_band_findings"]:
            lines.append(
                f"- {c['out_of_band_findings']} findings meet the CTI out-of-band "
                "policy: expedited lane"
            )
        if "rollout_gate" in c:
            lines.append(
                f"- preliminary rollout safety gate: {c['rollout_gate']} — "
                f"{c['rollout_gate_reason']}; execution remains unauthorized"
            )
            if c.get("rollout_waves"):
                shown_waves = c["rollout_waves"][:6]
                waves_summary = "; ".join(
                    f"{wave['role']} {wave['assets']} assets"
                    for wave in shown_waves
                )
                remaining = len(c["rollout_waves"]) - len(shown_waves)
                suffix = f"; plus {remaining} more" if remaining else ""
                lines.append(
                    f"- rollout: {len(c['rollout_waves'])} waves "
                    f"({waves_summary}{suffix})"
                )
        lines.append("")
    return "\n".join(lines)


def sample_estate() -> dict:
    return {
        "assets": [
            {"id": "vm-01", "name": "fr-srv-0001", "criticality": 6,
             "crown_jewel": False},
            {"id": "vm-02", "name": "us-srv-0002", "criticality": 9, "crown_jewel": True},
            {"id": "ct-01", "name": "payment-api", "criticality": 8, "crown_jewel": True,
             "externally_facing": True},
            {"id": "ct-02", "name": "svc-002", "criticality": 5,
             "crown_jewel": False},
        ],
        "findings": [
            {"id": "F-1", "asset_id": "vm-01", "severity": "high",
             "title": "OpenSSH regreSSHion", "cve": "CVE-2024-6387",
             "epss": 0.64, "patch_key": "openssh-9.8p1"},
            {"id": "F-2", "asset_id": "vm-02", "severity": "high",
             "title": "OpenSSH regreSSHion", "cve": "CVE-2024-6387",
             "epss": 0.64, "patch_key": "openssh-9.8p1"},
            # CVE-2024-3094 is deliberately NOT marked kev: the xz-utils backdoor
            # was caught before it reached stable distributions, so CISA never
            # listed it in the KEV catalog. CVSS 10.0 with a public POC and still
            # not "known exploited" -- severity plus exploit availability is a
            # different claim from observed exploitation, and keeping those two
            # apart is the whole point of scoring them separately.
            {"id": "F-3", "asset_id": "ct-01", "severity": "critical",
             "title": "xz-utils backdoor (base layer)", "cve": "CVE-2024-3094",
             "kev": False, "cvss": 10.0, "exploit_available": True,
             "base_image": "base-runtime:1.19"},
            {"id": "F-4", "asset_id": "ct-02", "severity": "critical",
             "title": "xz-utils backdoor (base layer)", "cve": "CVE-2024-3094",
             "kev": False, "cvss": 10.0, "exploit_available": True,
             "base_image": "base-runtime:1.19"},
        ],
    }


def demo_estate(seed: int = 1707) -> dict:
    """Small deterministic estate: enough shape to show a real collapse.

    Threat intel in here is a pinned snapshot: the kev flags were validated
    against the CISA Known Exploited Vulnerabilities catalog, version
    2026.08.03. Check live sources before acting on a real estate.
    """
    def rng():  # tiny LCG, deterministic without the random module's churn risk
        nonlocal state
        state = (state * 16807) % 2147483647
        return state / 2147483647
    state = seed
    # Site codes for a multinational that does not exist. Kept alphabetic so the
    # per-site rollout waves have something to group on.
    countries = ["us", "ca", "mx", "de", "es", "it"]
    assets, findings = [], []
    fid = 0
    for i in range(120):
        cc = countries[i % len(countries)]
        assets.append({"id": f"vm-{i:03d}", "name": f"{cc}-srv-{i:03d}",
                       "criticality": 4 + int(rng() * 4), "crown_jewel": False})
    assets.append({"id": "vm-erp", "name": "erp-db-01", "criticality": 10, "crown_jewel": True})
    # kev and exploit_available are separate columns on purpose: one records
    # observed exploitation (CISA KEV), the other mere availability. CVE-2024-3094
    # (xz backdoor) is CVSS 10.0 with a public POC yet NOT on KEV -- it was caught
    # before stable distributions shipped it. CVE-2023-44487 and CVE-2023-4911
    # are both on KEV.
    base_cves = [("CVE-2024-3094", "critical", False, True, 0.92, 10.0),
                 ("CVE-2023-44487", "high", True, True, 0.55, 7.5),
                 ("CVE-2023-4911", "high", True, True, 0.44, 7.8)]
    for i in range(30):
        ext = i < 3
        assets.append({"id": f"ct-{i:03d}", "name": f"svc-{i:03d}",
                       "criticality": 5 + (3 if ext else 0),
                       "crown_jewel": i == 0, "externally_facing": ext})
        for cve, sev, kev, exploit, epss, cvss in base_cves:
            fid += 1
            findings.append({"id": f"F-{fid:04d}", "asset_id": f"ct-{i:03d}", "severity": sev,
                             "title": f"{cve} inherited from base image", "cve": cve, "kev": kev,
                             "cvss": cvss, "epss": epss, "exploit_available": exploit,
                             "base_image": "base-runtime:1.19"})
    for i in range(60):
        fid += 1
        findings.append({"id": f"F-{fid:04d}", "asset_id": f"vm-{i:03d}", "severity": "high",
                         "title": "OpenSSH regreSSHion", "cve": "CVE-2024-6387", "epss": 0.64,
                         "patch_key": "openssh-9.8p1"})
    for i in range(40):
        fid += 1
        findings.append({"id": f"F-{fid:04d}", "asset_id": f"vm-{60+i:03d}", "severity": "critical",
                         "title": "KB5034763 missing", "cve": "CVE-2024-21412", "kev": True,
                         "patch_key": "KB5034763"})
    for i in range(25):
        fid += 1
        findings.append({"id": f"F-{fid:04d}", "asset_id": f"vm-{i*4:03d}", "severity": "medium",
                         "title": "Management port exposed", "security_group": "sg-open-mgmt"})
    for i in range(80):
        fid += 1
        findings.append({"id": f"F-{fid:04d}", "asset_id": f"vm-{int(rng()*120):03d}",
                         "severity": "medium" if rng() > 0.3 else "low",
                         "title": f"Misc advisory {i}"})
    return {"assets": assets, "findings": findings}


def main() -> int:
    ap = argparse.ArgumentParser(description="Chokepoint ranking, dependency-free.")
    ap.add_argument("estate", nargs="?", help="JSON file (see --sample); '-' for stdin")
    ap.add_argument("--top", type=int, default=7)
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    ap.add_argument("--sample", action="store_true", help="print the input schema by example")
    ap.add_argument("--demo", action="store_true", help="run on a built-in deterministic estate")
    ap.add_argument("--effort-weighted", action="store_true",
                    help="rank by marginal risk / sqrt(effort), a cost-benefit heuristic with "
                         "no approximation guarantee (default: pure marginal risk)")
    args = ap.parse_args()

    if args.sample:
        print(json.dumps(sample_estate(), indent=2))
        return 0
    if args.demo:
        estate = demo_estate()
    elif args.estate:
        raw = sys.stdin.read() if args.estate == "-" else open(args.estate, encoding="utf-8").read()
        estate = json.loads(raw)
    else:
        ap.print_help()
        return 2

    result = rank(estate, top=args.top, effort_weighted=args.effort_weighted)
    print(json.dumps(result, indent=2) if args.json else to_markdown(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
