#!/usr/bin/env python3
"""Generate the HTH↔OCEAN parity manifest (docs/PARITY-HTH.md companion).

Reads the sibling how-to-harden checkout and this repo's checks/ tree, emits
parity/hth-parity.json enumerating every HTH vendor: guide controls, pack
sections by type, matching OCEAN checks, and an honest status.

Usage: python3 scripts/hth_parity.py [--hth PATH] [--out PATH]
Requires: pyyaml (already a CI dependency for lint-content).
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parent.parent
DEFAULT_HTH = REPO.parent / "how-to-harden"

# HTH guide slug -> OCEAN checks/ dir where naming differs.
VENDOR_ALIASES = {
    "github": "github",
    "okta": "okta",
    "microsoft-entra-id": "azure",
}
# OCEAN check-id prefix -> HTH guide slug (for reverse matching).
PREFIX_TO_SLUG = {
    "GH": "github",
    "OKTA": "okta",
    "AWS": "aws",  # no HTH guide (AWS is out of HTH's SaaS scope) — native-only
    "AZURE": "microsoft-entra-id",
    "SNOW": "snowflake",  # no OCEAN checks yet — see parity report (transport not verifiable in-repo)
    "SLACK": "slack",
    "GITLAB": "gitlab",
    "OP": "1password",
    "SG": "sendgrid",
    "ZOOM": "zoom",
    "R7": "rapid7",
    "TEN": "tenable",
    "SAIL": "sailpoint",
    "OL": "onelogin",
    "NOTION": "notion",
    "PM": "postman",
    "DUO": "duo",  # no OCEAN checks — Admin API requires per-request HMAC-signed Authorization (ikey/skey), not a static bearer/basic token the check DSL can compute
    "VERCEL": "vercel",
    "JC": "jumpcloud",
    "SFDC": "salesforce",
    "CF": "cloudflare",
    "AUTH0": "auth0",
    "LD": "launchdarkly",
    "ANTH": "anthropic-claude",  # multi-guide family (anthropic-claude hub, anthropic-api, claude-code, claude-enterprise) — each check's references.hth carries the specific guide slug
    "CGPT": "chatgpt-enterprise",
    "WKTO": "workato",
}


def guide_controls(guide_path: Path) -> list[str]:
    """Control numbers (### N.N carrying **Profile Level:**) from an HTH guide."""
    text = guide_path.read_text(encoding="utf-8", errors="replace")
    controls: list[str] = []
    for section in re.split(r"^### (?=\d+\.\d+ )", text, flags=re.M)[1:]:
        num = section.split(" ", 1)[0]
        if re.match(r"^\d+\.\d+\.\d+", num):
            continue
        if "**Profile Level:**" in section:
            controls.append(num)
    return controls


def pack_sections(pack_yml: Path) -> dict[str, list[str]]:
    """section -> [pack types] from an HTH docs/_data/packs/<vendor>.yml."""
    data = yaml.safe_load(pack_yml.read_text(encoding="utf-8", errors="replace")) or {}
    out: dict[str, list[str]] = {}
    for section, entry in data.items():
        if not isinstance(entry, dict):
            continue
        types = [k for k in entry if k not in ("lang", "filename", "source_url")]
        out[str(section)] = sorted(types)
    return out


def ocean_checks() -> dict[str, list[dict]]:
    """HTH slug -> [{id, file, section}] from checks/**/*.check.yaml."""
    by_slug: dict[str, list[dict]] = {}
    for check in sorted((REPO / "checks").rglob("*.check.yaml")):
        try:
            data = yaml.safe_load(check.read_text(encoding="utf-8", errors="replace")) or {}
        except yaml.YAMLError:
            continue
        cid = str(data.get("id", check.stem))
        prefix = cid.split("-")[0]
        slug = PREFIX_TO_SLUG.get(prefix)
        # references.hth beats prefix inference when present.
        refs = data.get("references") or {}
        hth_ref = refs.get("hth")
        section = None
        if isinstance(hth_ref, str) and ":" in hth_ref:
            slug, section = hth_ref.split(":", 1)
        elif isinstance(hth_ref, str) and hth_ref:
            section = hth_ref
        if slug is None:
            slug = f"_unmapped/{prefix.lower()}"
        if section is None:
            m = re.search(r"-(\d+\.\d+)", cid)
            section = m.group(1) if m else None
        by_slug.setdefault(slug, []).append(
            {"id": cid, "file": str(check.relative_to(REPO)).replace("\\", "/"), "section": section}
        )
    return by_slug


def norm_section(section: str | None) -> str | None:
    """Normalize '1.01' (OCEAN check-id style) and '1.1' (HTH style) to '1.1'."""
    if not section:
        return section
    parts = section.split(".")
    if len(parts) == 2 and all(p.isdigit() for p in parts):
        return f"{int(parts[0])}.{int(parts[1])}"
    return section


def validate(manifest_path: Path) -> int:
    """CI mode: no HTH checkout needed. Validates the committed manifest against
    the checks/ tree — every check's references.hth must resolve to a real
    control in the manifest, and per-vendor check counts must match reality."""
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    by_vendor = {v["vendor"]: v for v in manifest["vendors"]}
    checks = ocean_checks()
    errors: list[str] = []

    for slug, vendor_checks in checks.items():
        if slug.startswith("_unmapped/") or slug not in by_vendor:
            continue
        known = {norm_section(c) for c in by_vendor[slug]["controls"]}
        for chk in vendor_checks:
            sec = norm_section(chk["section"])
            # "vendor:none" is the explicit no-current-HTH-section sentinel
            # (e.g. GH-5.01 org-webhooks) — deliberately unmapped, never an error.
            if sec == "none":
                continue
            if sec and known and sec not in known:
                errors.append(
                    f"{chk['file']}: references section {sec} not in HTH {slug} controls"
                )

    for v in manifest["vendors"]:
        alias = VENDOR_ALIASES.get(v["vendor"], "")
        actual = len(checks.get(v["vendor"], []) + checks.get(alias, []))
        if actual != len(v["ocean_checks"]):
            errors.append(
                f"{v['vendor']}: manifest lists {len(v['ocean_checks'])} checks, tree has {actual} — regenerate (scripts/hth_parity.py)"
            )

    if errors:
        print("parity validate: FAIL", file=sys.stderr)
        for e in errors:
            print(f"  {e}", file=sys.stderr)
        return 1
    print(f"parity validate: OK ({manifest['totals']['checks']} mapped checks consistent)")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--hth", type=Path, default=DEFAULT_HTH)
    ap.add_argument("--out", type=Path, default=REPO / "parity" / "hth-parity.json")
    ap.add_argument("--validate", action="store_true",
                    help="validate committed manifest against checks/ (no HTH checkout needed)")
    args = ap.parse_args()

    if args.validate:
        return validate(args.out)

    guides_dir = args.hth / "docs" / "_guides"
    packs_dir = args.hth / "docs" / "_data" / "packs"
    if not guides_dir.is_dir():
        print(f"error: HTH guides not found at {guides_dir}", file=sys.stderr)
        return 2

    checks = ocean_checks()
    vendors = []
    totals = {"guides": 0, "controls": 0, "pack_vendors": 0, "pack_sections": 0,
              "checks": 0, "controls_covered": 0}

    for guide in sorted(guides_dir.glob("*.md")):
        slug = guide.stem
        controls = guide_controls(guide)
        pack_yml = packs_dir / f"{slug}.yml"
        packs = pack_sections(pack_yml) if pack_yml.is_file() else {}
        vendor_checks = checks.get(slug, []) + checks.get(VENDOR_ALIASES.get(slug, ""), [])
        covered = {norm_section(c["section"]) for c in vendor_checks if c["section"]}
        controls_covered = [c for c in controls if norm_section(c) in covered]

        if vendor_checks and controls and len(controls_covered) == len(controls):
            status = "full"
        elif vendor_checks:
            status = "partial"
        else:
            status = "missing"

        vendors.append({
            "vendor": slug,
            "status": status,
            "guide_controls": len(controls),
            "controls": controls,
            "pack_sections": packs,
            "ocean_checks": vendor_checks,
            "controls_covered": controls_covered,
        })
        totals["guides"] += 1
        totals["controls"] += len(controls)
        totals["controls_covered"] += len(controls_covered)
        totals["pack_sections"] += len(packs)
        if packs:
            totals["pack_vendors"] += 1
        totals["checks"] += len(vendor_checks)

    unmapped = {k: v for k, v in checks.items() if k.startswith("_unmapped/") or k == "aws"}
    manifest = {
        "generated_by": "scripts/hth_parity.py",
        "hth_repo": str(args.hth),
        "totals": totals,
        "vendors": vendors,
        "ocean_only": unmapped,
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")

    full = sum(1 for v in vendors if v["status"] == "full")
    partial = sum(1 for v in vendors if v["status"] == "partial")
    print(f"parity manifest → {args.out}")
    print(f"vendors: {totals['guides']} (full {full} / partial {partial} / missing {totals['guides']-full-partial})")
    print(f"controls: {totals['controls_covered']}/{totals['controls']} covered · ocean checks mapped: {totals['checks']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
