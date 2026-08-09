# HTH Parity — Decision & Program

**Date:** 2026-08-09 · **Status:** Accepted (implements ADR-001's end state)
**Companion artifacts:** `parity/hth-parity.json` (generated manifest), `scripts/hth_parity.py` (generator)

## The question

How To Harden ships 125 hardening guides and 71 vendors' worth of code packs
(api/cli/sdk/terraform/config/db/siem-sigma files keyed to guide control numbers).
OCEAN ships 72 `.check.yaml` checks across 4 vendors. Should HTH code packs become
OCEAN "modules" directly, should OCEAN keep its own module framework and duplicate
the packs, or a mix?

## Decision

**OCEAN-native `.check.yaml` is the one module framework. HTH code packs are
treated as verified *specifications* to derive checks from, and as *generated
artifacts* going forward — never vendored in as modules.** This is a mix, leaning
native:

1. **ADR-001 already decided the architecture** (accepted 2026-03-28): the unified
   check format is the single source of truth precisely because maintaining the
   same check logic in two forms is the drift machine that motivated the merger.
   Importing ~600 hand-written pack files as first-class modules would rebuild
   that machine inside OCEAN.
2. **The codegen targets already mirror HTH's pack taxonomy** — api-script↔`api/`,
   gh-cli↔`cli/` (GitHub), python-sdk↔`sdk/`, terraform↔`terraform/`,
   sigma-rule↔`siem/sigma/`, opa-rego (no HTH equivalent; additive). One check
   file regenerates every pack shape HTH distributes.
3. **HTH packs are fetch-verified content** (every endpoint verified against vendor
   docs under HTH's authoring standards). That makes them the *ideal derivation
   source* for check `steps:`/`assertions:`/`remediation:` blocks — the research
   is already done and quality-gated; parity work is translation, not invention.
4. **The mix:** HTH keeps publishing packs on howtoharden.com (its consumption
   model); the parity manifest links every HTH control to its OCEAN check; the
   ADR-001 end state — `ocean build` output replacing hand-written packs upstream —
   becomes reachable vendor-by-vendor once a vendor's checks reach parity.

## Parity accounting (honest coverage, not silent partials)

`scripts/hth_parity.py` reads the HTH repo (sibling checkout) and emits
`parity/hth-parity.json`: every HTH vendor with guide-control inventory, pack
sections by type, matching OCEAN checks, and a status of `full`, `partial`, or
`missing`. CI can re-run it; the manifest is the single honest statement of how
far parity has progressed. Anything not yet covered is *visible*, never implied
covered.

## Authoring contract (every new check)

- Derived from the HTH pack/control content (verified source), with the guide
  control ID recorded in `references.hth`.
- TDD per `tests/check_pipeline.rs` pattern: MockHTTPServer, pass case + fail
  case fixtures derived from the vendor's documented API responses; tests land
  with (or before) the check.
- No fabricated endpoints: if HTH has no pack for a control and the vendor API
  surface is unverified, the check is NOT authored; the manifest keeps it
  `missing` with a reason.
- Safety: testers carry safety classifications; observers default `safe`.
