# GRC Schema & Framework Data Model Research

**Date**: 2026-02-27
**Researcher**: Ava Chen (Investigative Analyst)
**Purpose**: Deep technical analysis of GRC data models and schema designs to inform OCEAN's evidence normalization layer
**Scope**: NIST OSCAL, OpenControl, MITRE ATT&CK, CSA CCM, Gap Analysis

---

## Table of Contents

1. [NIST OSCAL](#1-nist-oscal)
2. [OpenControl](#2-opencontrol)
3. [MITRE ATT&CK](#3-mitre-attck)
4. [CSA CCM](#4-csa-ccm)
5. [Gap Analysis: What OCEAN Uniquely Provides](#5-gap-analysis)
6. [Design Implications for OCEAN](#6-design-implications)

---

## 1. NIST OSCAL

**Full Name**: Open Security Controls Assessment Language
**Maintained by**: NIST (National Institute of Standards and Technology)
**Current Version**: 1.1.2
**Format**: JSON, XML, YAML (lossless conversion between all three)
**Source**: https://pages.nist.gov/OSCAL/

### 1.1 The Six Models Across Three Layers

OSCAL organizes into **three layers**, each containing models that build on the previous:

```
LAYER 1: CONTROL LAYER
  +-- Catalog Model
  +-- Profile Model

LAYER 2: IMPLEMENTATION LAYER
  +-- Component Definition Model
  +-- System Security Plan (SSP) Model

LAYER 3: ASSESSMENT LAYER
  +-- Assessment Plan Model
  +-- Assessment Results Model
```

**Catalog Model** (Layer 1)
- Defines controls from any framework (NIST 800-53, ISO 27001, CIS, etc.)
- Structure: `catalog > groups > controls > parts > parameters`
- Controls have: `id`, `class`, `title`, `params`, `props`, `parts` (statements, guidance, objectives)
- This is the foundation -- all other models reference catalogs

**Profile Model** (Layer 1)
- Selects and tailors controls from one or more catalogs into a baseline/overlay
- Structure: `profile > imports > merge > modify`
- `imports`: references catalog(s) with `include-controls` / `exclude-controls` selectors
- `modify`: parameter settings, control alterations, additions
- Example: FedRAMP High = NIST 800-53 catalog filtered to FedRAMP-relevant controls with parameter values set

**Component Definition Model** (Layer 2)
- Describes how a component (hardware, software, service, policy) satisfies controls
- Structure: `component-definition > components > control-implementations > implemented-requirements`
- A component declares: `type` (software, hardware, service, policy, process, plan, guidance, standard, validation), `title`, `description`, `props`, `responsible-roles`
- `implemented-requirements` links a `control-id` to narratives and `statements`

**System Security Plan (SSP) Model** (Layer 2)
- Full system security documentation linking components to a specific baseline
- Structure: `system-security-plan > system-characteristics + system-implementation + control-implementation`
- `system-implementation > components + inventory-items + users`
- `control-implementation > implemented-requirements` (per-control narratives with `by-component` breakdowns)

**Assessment Plan Model** (Layer 3)
- Defines what will be assessed and how
- Structure: `assessment-plan > reviewed-controls + assessment-subjects + assessment-assets + tasks`
- `tasks` define activities: `type` (action, milestone), `timing` (on-date, within-date-range, at-frequency)
- Assessment methods: EXAMINE, INTERVIEW, TEST

**Assessment Results Model** (Layer 3)
- Documents what was found during assessment -- this is the model most relevant to OCEAN
- See detailed structure below

### 1.2 Assessment Results Model -- Deep Structure

The Assessment Results model is the most complex and the most relevant to OCEAN's evidence model. Its structure:

```
assessment-results
  +-- uuid
  +-- metadata (title, version, roles, parties, responsible-parties)
  +-- import-ap (reference to Assessment Plan)
  +-- local-definitions (components, users, activities, objectives-and-methods)
  +-- results[] (one per assessment period)
      +-- uuid
      +-- title
      +-- description
      +-- start (date-time)
      +-- end (date-time)
      +-- props[]
      +-- reviewed-controls (control-selections with include/exclude)
      +-- assessment-subjects[] (type: component, inventory-item, location, party, user)
      +-- assessment-assets (assessment-platforms, components)
      +-- attestations[] (responsible-parties + parts)
      +-- assessment-log
      |   +-- entries[]
      |       +-- uuid, title, description, start, end
      |       +-- logged-by[] (party-uuid, role-id)
      |       +-- related-tasks[] (task-uuid, subjects, identified-subject)
      +-- observations[]
      |   +-- uuid
      |   +-- title
      |   +-- description
      |   +-- props[]
      |   +-- links[]
      |   +-- methods[] (EXAMINE | INTERVIEW | TEST)
      |   +-- types[] (ssp-statement-issue | control-objective | historic | finding)
      |   +-- origins[] (actors with type: tool | party | assessment-platform)
      |   +-- subjects[] (subject-uuid, type, title, props, links)
      |   +-- relevant-evidence[]
      |   |   +-- href (URI reference to back-matter resource or external URL)
      |   |   +-- description (required)
      |   |   +-- props[]
      |   |   +-- links[]
      |   |   +-- remarks
      |   +-- collected (date-time-with-timezone, required)
      |   +-- expires (date-time-with-timezone, optional)
      |   +-- remarks
      +-- risks[]
      |   +-- uuid
      |   +-- title
      |   +-- description
      |   +-- statement (risk statement)
      |   +-- props[]
      |   +-- links[]
      |   +-- status (open | investigating | remediating | deviation-requested |
      |   |           deviation-approved | closed)
      |   +-- origins[]
      |   +-- threat-ids[] (system: URI, id: string)
      |   +-- characterizations[]
      |   |   +-- origin
      |   |   +-- facets[] (name, system, value, props with state: initial | adjusted)
      |   +-- mitigating-factors[]
      |   |   +-- uuid, implementation-uuid, description, subjects[], links[]
      |   +-- deadline (date-time)
      |   +-- remediations[] (lifecycle: recommendation | planned | completed)
      |   +-- risk-log
      |   |   +-- entries[] (uuid, title, description, start, end, logged-by[],
      |   |                   status-change, related-responses[])
      |   +-- related-observations[] (observation-uuid)
      +-- findings[]
          +-- uuid
          +-- title (required)
          +-- description (required)
          +-- props[]
          +-- links[]
          +-- origins[] (actors who generated the finding)
          +-- target (required)
          |   +-- type (objective-id | finding)
          |   +-- target-id (references a control objective)
          |   +-- title
          |   +-- description
          |   +-- props[]
          |   +-- links[]
          |   +-- status (required)
          |       +-- state (satisfied | not-satisfied)
          |       +-- reason (pass | fail | other)
          |       +-- remarks
          +-- implementation-statement-uuid (links to SSP implemented-requirement)
          +-- related-observations[] (observation-uuid references)
          +-- associated-risks[] (risk-uuid references)
          +-- remarks
```

### 1.3 Key Relationship Pattern: Findings --> Observations --> Evidence

The OSCAL assessment results uses a **three-tier linkage** pattern:

```
Finding (verdict on a control objective)
  |-- target.status.state = "satisfied" | "not-satisfied"
  |-- related-observations[] --> observation-uuid (many-to-many)
  |-- associated-risks[] --> risk-uuid (many-to-many)
  |
  v
Observation (what was seen)
  |-- methods[] = ["EXAMINE", "INTERVIEW", "TEST"]
  |-- subjects[] = what was looked at
  |-- relevant-evidence[] --> href to actual evidence artifacts
  |-- collected = timestamp
  |
  v
Risk (what could go wrong)
  |-- status = "open" | "investigating" | "remediating" | "closed"
  |-- characterizations[].facets[] = risk scoring (CVSS, custom)
  |-- related-observations[] --> back-reference to observations
```

Key design decisions:
- **Findings are the verdict layer** -- they say "satisfied" or "not-satisfied" for a control objective
- **Observations are the evidence layer** -- they record what was actually seen/tested/examined
- **Risks are the consequence layer** -- they track identified risks with lifecycle management
- All three are **peer-level arrays** within a `result` -- linked by UUID cross-references, not nesting
- **Evidence is an attachment pattern** -- `relevant-evidence.href` points to `back-matter.resources` or external URIs, not inline data

### 1.4 Assessment Methods

OSCAL defines exactly three assessment methods (from NIST SP 800-53A):
- **EXAMINE**: Review/inspect/analyze documents, mechanisms, activities
- **INTERVIEW**: Hold discussions with individuals or groups
- **TEST**: Exercise assessment objects under specified conditions to compare actual vs expected behavior

The `TEST` method is the closest analog to OCEAN's active testing concept, but OSCAL treats it as a method annotation on an observation, not as a first-class behavioral verification with safety classifications, pre-flight checks, and cleanup procedures.

### 1.5 OSCAL Limitations (What It Does NOT Solve)

**Structural/Architectural Limitations:**
1. **No live evidence capture** -- OSCAL models evidence as href references to documents/attachments. It has no concept of structured, queryable evidence data collected from APIs in real-time. Evidence is "point to a file," not "here is the actual configuration state in a normalized schema."

2. **No evidence normalization schema** -- OSCAL has no equivalent to OCSF's event class taxonomy. An observation's `description` is free-text. Two observations about MFA enforcement from different systems will have completely different structures.

3. **No active testing semantics** -- While the `TEST` method exists, OSCAL has no safety classification (safe/observable/reversible/destructive), no pre-flight validation, no cleanup procedures, no test transcripts, no concept of "attempt what controls should prevent."

4. **No continuous monitoring data model** -- OSCAL is snapshot-oriented. The `results` array can hold multiple assessment periods, but there is no time-series model, no uptime calculations, no change detection, no scheduled collection.

5. **No evaluation logic** -- OSCAL records the verdict (satisfied/not-satisfied) but has no mechanism to define HOW that verdict was computed. No CEL expressions, no evaluation rules, no reproducible logic.

6. **No confidence levels** -- A finding is either "satisfied" or "not-satisfied." There is no concept of confidence (e.g., passive observation vs active verification carrying different weights).

7. **Component-level redundancy** -- Every component must individually document all associated controls, creating substantial duplication in complex environments.

8. **No provenance chain** -- OSCAL has `origins` (who performed the assessment) but no cryptographic provenance, no content-addressable evidence, no chain-of-custody beyond text metadata.

**Adoption Limitations:**
- Steep learning curve requiring specialized knowledge
- Limited tooling ecosystem (NIST waited for industry to build tools)
- Organizations accustomed to Excel/manual processes resist adoption
- Immature continuous monitoring tooling around OSCAL

---

## 2. OpenControl

**Full Name**: OpenControl (Compliance as Code)
**Maintained by**: OpenControl community (largely inactive/deprecated as of 2024+)
**Current Schema Version**: 3.0.0 (component), 1.0.0 (opencontrol.yaml)
**Format**: YAML only
**Source**: https://github.com/opencontrol/schemas

### 2.1 Core Philosophy

OpenControl was built on the premise that compliance documentation should live alongside code in version control. Every commit runs tests, every passing build updates the system security plan, every deployment includes continuous monitoring updates.

The key insight: **control satisfaction narratives are code artifacts that should be versioned, reviewed, and tested like any other code.**

### 2.2 Schema Elements

**opencontrol.yaml** (project root -- aggregates everything):
```yaml
schema_version: "1.0.0"
name: "My System"
metadata:
  description: "System description"
  maintainers:
    - email: "admin@example.com"
components:
  - ./component-dir        # local paths to component.yaml files
certifications:
  - ./certifications/      # local paths
standards:
  - ./standards/           # local paths
dependencies:
  certifications:
    - url: "https://github.com/org/repo"
      revision: "main"
      contextdir: "certifications/"
  systems:
    - url: "https://github.com/org/other-system"
      revision: "v1.0"
  standards:
    - url: "https://github.com/opencontrol/standards"
      revision: "master"
```

**standard.yaml** (defines a framework's controls):
```yaml
name: NIST-800-53
standards:
  NIST-800-53:
    AC-1:
      name: "Access Control Policy and Procedures"
      description: "The organization develops, documents, and disseminates..."
    AC-2:
      name: "Account Management"
      description: "The organization manages information system accounts..."
```

**component.yaml** (the core schema -- how a component satisfies controls):
```yaml
schema_version: "3.0.0"
name: "AWS EC2"
key: "EC2"               # optional, defaults to directory name
documentation_complete: false
references:
  - name: "AWS EC2 Documentation"
    path: "https://docs.aws.amazon.com/ec2/"
    type: "URL"
verifications:
  - key: "EC2_SCAN"
    name: "Nessus scan results"
    path: "./scans/ec2-latest.pdf"
    type: "Image"
satisfies:
  - standard_key: "NIST-800-53"
    control_key: "AC-2"
    narrative:
      - key: "a"
        text: "EC2 instances use IAM roles for access control..."
      - key: "b"
        text: "Account provisioning is managed through..."
    implementation_statuses:
      - "complete"        # partial | planned | complete | none
    control_origins:
      - "shared"          # shared | inherited | other
    parameters:
      - key: "AC-2_frequency"
        text: "annually"
    covered_by:
      - verification_key: "EC2_SCAN"
        system_key: "my-system"
        component_key: "EC2"
```

### 2.3 Control Satisfaction Model

The `satisfies` array is the heart of OpenControl. Each entry binds:
- A `standard_key` + `control_key` pair (which framework control)
- `narrative[]` with `key` + `text` (HOW it is satisfied, keyed to control parts a, b, c, etc.)
- `implementation_statuses[]` = `partial | planned | complete | none`
- `control_origins[]` = `shared | inherited | other`
- `parameters[]` for control parameter values
- `covered_by[]` linking to verification evidence

### 2.4 Evidence References

OpenControl handles evidence through two mechanisms:

**References** (supporting documentation):
```yaml
references:
  - name: "Architecture Diagram"
    path: "docs/architecture.png"     # relative path or URL
    type: "Image"                      # Image | URL
```

**Verifications** (evidence that a control is working):
```yaml
verifications:
  - key: "MFA_CHECK"
    name: "MFA enforcement scan"
    path: "reports/mfa-scan.json"
    type: "URL"
```

**`covered_by`** in `satisfies` links a control satisfaction claim to specific verifications.

### 2.5 OpenControl Limitations

1. **Static narratives only** -- Control satisfaction is expressed as text narratives, not as queryable evidence data. "EC2 uses IAM roles" is prose, not a machine-evaluable assertion.

2. **No structured evidence schema** -- Evidence is file references (paths/URLs). The content and format of evidence is completely unstructured. A "verification" is just a pointer to a file.

3. **No evaluation logic** -- `implementation_statuses` is a manually-set enum (`complete`, `partial`, etc.). There is no automated evaluation, no CEL expressions, no computed verdicts.

4. **No temporal dimension** -- No timestamps on evidence, no time-series, no historical tracking, no uptime calculations. It is entirely point-in-time.

5. **No active testing** -- No concept of behavioral verification, safety classifications, test transcripts, or cleanup procedures.

6. **No evidence provenance** -- No chain of custody, no content addressing, no attestation. The `covered_by` link is a trust-me pointer.

7. **Effectively deprecated** -- The OpenControl GitHub organization shows minimal activity since 2020. Industry has largely moved to OSCAL. The compliance-masonry tool (the main consumer) has an open issue (#343) about migrating to OSCAL.

8. **No API integration** -- OpenControl assumes all data is authored by humans in YAML. There is no concept of automated collection from system APIs.

---

## 3. MITRE ATT&CK

**Full Name**: MITRE ATT&CK (Adversarial Tactics, Techniques, and Common Knowledge)
**Maintained by**: The MITRE Corporation
**Current Version**: v18 (Enterprise)
**Format**: STIX 2.1 JSON
**Source**: https://attack.mitre.org/ | https://github.com/mitre-attack/attack-stix-data

### 3.1 Taxonomy Hierarchy

ATT&CK uses a three-level hierarchy that is a masterclass in taxonomy design:

```
Matrix (domain)
  +-- Tactic (the WHY -- adversary's goal)
      +-- Technique (the HOW -- method to achieve goal)
          +-- Sub-Technique (the SPECIFIC HOW -- granular variant)
```

**Current Scale** (v18 Enterprise):
- 14 Tactics
- 216 Techniques
- 475 Sub-Techniques
- ~700 total technique/sub-technique entries

### 3.2 ID Format

ATT&CK uses a clean, hierarchical ID system:

```
Tactics:        TA00XX    (e.g., TA0001 = Initial Access)
Techniques:     T1XXX     (e.g., T1059  = Command and Scripting Interpreter)
Sub-Techniques: T1XXX.YYY (e.g., T1059.003 = Windows Command Shell)
Mitigations:    M1XXX     (e.g., M1038  = Execution Prevention)
Data Sources:   DS00XX    (e.g., DS0009 = Process)
Groups:         G00XX     (e.g., G0007  = APT28)
Software:       S0XXX     (e.g., S0154  = Cobalt Strike)
```

The **dot notation for sub-techniques** (T1059.003) is particularly elegant -- it preserves the parent relationship in the ID itself while allowing independent evolution.

### 3.3 STIX 2.1 Object Structure (attack-pattern)

Each ATT&CK technique is represented as a STIX `attack-pattern` object. Based on the ATT&CK Data Model specification and repository analysis, the complete field set is:

```json
{
  "type": "attack-pattern",
  "spec_version": "2.1",
  "id": "attack-pattern--d1fcf083-a721-4223-aedf-bf8960798d62",
  "created": "2017-05-31T21:30:44.329Z",
  "modified": "2024-04-16T12:27:43.109Z",
  "created_by_ref": "identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5",
  "revoked": false,
  "object_marking_refs": ["marking-definition--fa42a846-8d90-4e51-bc29-71d5b4802168"],

  "name": "Command and Scripting Interpreter",
  "description": "Adversaries may abuse command and script interpreters...",

  "kill_chain_phases": [
    {
      "kill_chain_name": "mitre-attack",
      "phase_name": "execution"
    }
  ],

  "external_references": [
    {
      "source_name": "mitre-attack",
      "external_id": "T1059",
      "url": "https://attack.mitre.org/techniques/T1059"
    },
    {
      "source_name": "Some Paper",
      "description": "Author. (Year). Title.",
      "url": "https://example.com/paper.pdf"
    }
  ],

  "x_mitre_platforms": ["Windows", "macOS", "Linux", "Network", "Office Suite"],
  "x_mitre_data_sources": [
    "Command: Command Execution",
    "Process: Process Creation",
    "Script: Script Execution"
  ],
  "x_mitre_detection": "Monitor command-line activity for...",
  "x_mitre_is_subtechnique": false,
  "x_mitre_version": "2.5",
  "x_mitre_deprecated": false,
  "x_mitre_domains": ["enterprise-attack"],
  "x_mitre_modified_by_ref": "identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5",
  "x_mitre_attack_spec_version": "3.2.0",
  "x_mitre_permissions_required": ["User"],
  "x_mitre_remote_support": false,
  "x_mitre_contributors": ["Contributor Name"]
}
```

### 3.4 Relationship Types

ATT&CK connects objects through STIX `relationship` objects:

| Relationship Type   | Source              | Target              | Meaning                                    |
|---------------------|---------------------|----------------------|--------------------------------------------|
| `uses`              | intrusion-set       | attack-pattern       | Group uses this technique                  |
| `uses`              | malware/tool        | attack-pattern       | Software implements this technique         |
| `mitigates`         | course-of-action    | attack-pattern       | Mitigation addresses this technique        |
| `subtechnique-of`   | attack-pattern      | attack-pattern       | Sub-technique belongs to parent technique  |
| `detects`           | x-mitre-data-component | attack-pattern    | Data component can detect this technique   |
| `revoked-by`        | attack-pattern      | attack-pattern       | Old technique replaced by new one          |

### 3.5 Data Sources Model

ATT&CK v10+ introduced a structured data source model:

```
Data Source (e.g., DS0009 "Process")
  +-- Data Component (e.g., "Process Creation", "Process Access")
      +-- detects --> Technique
```

Each technique's `x_mitre_data_sources` array uses the format `"Data Source: Data Component"` (e.g., `"Process: Process Creation"`).

There are 30+ data sources containing 90+ data components in the current Enterprise matrix.

### 3.6 Why ATT&CK's Taxonomy Works So Well

ATT&CK's design is the gold standard for security taxonomy. The key design patterns worth borrowing:

1. **Goal-oriented hierarchy**: Tactics = WHY (goals), Techniques = HOW (methods). This separates intent from implementation, enabling mapping across different technology stacks.

2. **Stable parent, evolving children**: Tactics rarely change. Techniques change occasionally. Sub-techniques change frequently. This gives the taxonomy stability at the top and granularity at the bottom.

3. **Self-documenting IDs**: T1059.003 tells you immediately this is sub-technique 003 of technique T1059. No lookup table needed for hierarchy.

4. **Rich metadata per node**: Every technique carries platforms, data sources, detection guidance, mitigations, references. The node is self-contained.

5. **Relationship-based composition**: Instead of deeply nested objects, ATT&CK uses flat objects with typed relationships. This enables any object to participate in multiple relationships without duplication.

6. **Real-world grounding**: Every technique is based on observed adversary behavior, not theoretical risk. This keeps the taxonomy practical and actionable.

7. **Versioned evolution**: `x_mitre_version` per object allows independent evolution. Techniques can be updated without changing the overall matrix version.

8. **Multi-domain**: The same taxonomy structure works across Enterprise, Mobile, and ICS domains with domain-specific content.

---

## 4. CSA CCM

**Full Name**: Cloud Security Alliance Cloud Controls Matrix
**Maintained by**: Cloud Security Alliance (CSA)
**Current Version**: v4.1
**Format**: Excel (primary), JSON/YAML/OSCAL (machine-readable)
**Source**: https://cloudsecurityalliance.org/research/cloud-controls-matrix

### 4.1 Domain Structure

CCM v4.1 organizes 207 control objectives across 17 security domains:

| # | Code | Domain Name                                                    |
|---|------|----------------------------------------------------------------|
| 1 | A&A  | Audit & Assurance                                              |
| 2 | AIS  | Application & Interface Security                                |
| 3 | BCR  | Business Continuity Management & Operational Resilience         |
| 4 | CCC  | Change Control & Configuration Management                      |
| 5 | CEK  | Cryptography, Encryption & Key Management                      |
| 6 | DCS  | Datacenter Security                                            |
| 7 | DSP  | Data Security & Privacy Lifecycle Management                   |
| 8 | GRC  | Governance, Risk Management & Compliance                       |
| 9 | HRS  | Human Resources Security                                       |
|10 | IAM  | Identity & Access Management                                   |
|11 | IPY  | Interoperability & Portability                                 |
|12 | IVS  | Infrastructure & Virtualization Security (renamed I&S in v4.1) |
|13 | LOG  | Logging & Monitoring                                           |
|14 | SEF  | Security Incident Management, E-Discovery & Cloud Forensics   |
|15 | STA  | Supply Chain Management, Transparency & Accountability         |
|16 | TVM  | Threat & Vulnerability Management                              |
|17 | UEM  | Universal Endpoint Management                                  |

### 4.2 Control ID Format

CCM uses a `[DOMAIN_CODE]-[SEQUENTIAL_NUMBER]` format:

```
AIS-01  Application Security                (1st control in Application & Interface Security)
AIS-02  Application Security Design         (2nd control)
AIS-03  Application Security Metrics        (3rd control)
AIS-04  Secure Application Development Lifecycle
...
DSI-02  Data Encryption at Rest/Transit/Processing
IAM-02  Regular Access Reviews
LOG-01  Logging and Monitoring Requirements
```

Each control objective has:
- **Control ID**: `[DOMAIN]-[NN]` format
- **Control Title**: Short name
- **Control Specification**: Detailed description of what the control requires
- **Implementation Guidance**: How to implement
- **Applicability**: Which service models (IaaS, PaaS, SaaS) and which party (CSP, CSC) is responsible
- **Framework Mappings**: Cross-references to other standards

### 4.3 Framework Mapping Model

CCM provides bidirectional mappings to major frameworks. Each control includes mapping columns for:

| Mapped Framework                    | Mapping Type |
|-------------------------------------|-------------|
| ISO/IEC 27001:2022                  | Clause/Control |
| ISO/IEC 27017:2015                  | Clause/Control |
| ISO/IEC 27018:2019                  | Clause/Control |
| NIST SP 800-53 Rev. 5              | Control Family + Number |
| NIST Cybersecurity Framework (CSF)  | Function.Category.Subcategory |
| CIS Controls v8                     | Control + Safeguard |
| SOC 2 Trust Services Criteria       | CC/A/C criteria |
| PCI DSS v4.0                        | Requirement number |
| HIPAA                               | Section reference |
| AICPA TSC 2017                      | Criteria reference |

The mapping is a **static lookup table** -- each CCM control has pre-determined mappings to corresponding controls in other frameworks. This is maintained by CSA working groups and updated with each CCM version.

**Machine-readable formats**: CCM v4.1 provides JSON/YAML and OSCAL-formatted versions for automation. The OSCAL version uses the Catalog model with CCM controls expressed as OSCAL controls with framework mappings as properties.

### 4.4 CCM Limitations

1. **No evidence model** -- CCM defines WHAT to control but has no schema for HOW to prove it. It is a controls catalog, not an evidence format.

2. **Static mappings** -- Framework mappings are maintained by committee and versioned with CCM releases. They cannot be dynamically extended or customized per-organization.

3. **Cloud-centric** -- Designed specifically for cloud security. Does not cover on-premises, OT/ICS, or general enterprise controls comprehensively.

4. **No assessment results model** -- Unlike OSCAL, CCM has no way to express "this control was assessed and found effective/ineffective." It is purely a control catalog.

5. **No automation semantics** -- Despite machine-readable formats, CCM does not define how controls should be tested, what evidence looks like, or how to evaluate compliance programmatically.

6. **Spreadsheet-first design** -- The primary distribution format is Excel. The JSON/YAML/OSCAL versions are secondary exports, not the authoritative source.

---

## 5. Gap Analysis: What OCEAN Uniquely Provides

After analyzing all four frameworks/schemas, there are clear gaps that none of them address. These gaps are precisely where OCEAN creates unique value.

### 5.1 Gap Matrix

| Capability                                    | OSCAL | OpenControl | ATT&CK | CCM  | OCEAN |
|-----------------------------------------------|-------|-------------|---------|------|-------|
| Control catalog / definition                  | Yes   | Yes         | N/A     | Yes  | No*   |
| Control satisfaction narratives               | Yes   | Yes         | No      | No   | No*   |
| Structured evidence data with schema          | **No**| **No**      | N/A     | **No**| **Yes** |
| Live evidence from API collection             | **No**| **No**      | N/A     | **No**| **Yes** |
| Evidence normalization taxonomy (OCSF-style)  | **No**| **No**      | Partial | **No**| **Yes** |
| Active control testing (behavioral)           | **No**| **No**      | Partial | **No**| **Yes** |
| Safety classifications for tests              | **No**| **No**      | **No**  | **No**| **Yes** |
| Test transcripts with cleanup                 | **No**| **No**      | **No**  | **No**| **Yes** |
| Evaluation logic (CEL / expressions)          | **No**| **No**      | N/A     | **No**| **Yes** |
| Time-series / uptime calculations             | **No**| **No**      | N/A     | **No**| **Yes** |
| Confidence levels (passive vs active)         | **No**| **No**      | N/A     | **No**| **Yes** |
| Evidence provenance chain                     | Partial| **No**     | N/A     | **No**| **Yes** (via Corsair) |
| Framework mappings                            | Yes   | Yes         | Partial | Yes  | Yes   |
| Assessment workflow                           | Yes   | **No**      | N/A     | **No**| Partial |
| Change detection / alerting                   | **No**| **No**      | N/A     | **No**| **Yes** |
| Continuous monitoring native                  | **No**| **No**      | N/A     | **No**| **Yes** |
| Cross-platform portability                    | Yes   | Yes         | Yes     | No   | Yes   |

*OCEAN consumes control catalogs from OSCAL/CCM; it does not define its own.

### 5.2 The Three Fundamental Gaps

**Gap 1: No Live Evidence with Provenance**

All existing frameworks treat evidence as either:
- **File references** (OSCAL `relevant-evidence.href`, OpenControl `verifications.path`)
- **Narrative text** (OSCAL `observation.description`, OpenControl `narrative.text`)
- **Not addressed** (CCM has no evidence model at all)

None of them capture evidence as **structured, queryable, API-collected data** with:
- Normalized schema (OCSF-style event classes)
- Collection metadata (source system, module version, API response hash)
- Temporal dimension (collected-at, expires, time-series history)
- Confidence indicators (passive observation vs active verification)

OCEAN fills this gap by defining evidence as first-class structured data, not file pointers.

**Gap 2: No Active Testing with Safety Semantics**

OSCAL has `TEST` as an assessment method, but it is just an annotation -- there are no semantics for:
- **Safety classification** (safe/observable/reversible/destructive)
- **Pre-flight validation** (scope check, authorization, rollback readiness)
- **Test execution transcripts** (what was attempted, what was observed, what was cleaned up)
- **Environment scoping** (production-safe vs staging-only)
- **Behavioral verification** (attempting what controls should prevent to prove they work)

ATT&CK describes adversary techniques that are conceptually similar to active tests, but ATT&CK is a threat knowledge base, not a testing framework. It does not define how to EXECUTE techniques safely for compliance verification.

OCEAN fills this gap with the Tester module type -- Metasploit-style active verification with safety-first design.

**Gap 3: No OCSF-Style Event Class Taxonomy for GRC Evidence**

OCSF (Open Cybersecurity Schema Framework) revolutionized security telemetry normalization with its hierarchical taxonomy:
```
Category > Class > Activity > Attributes
```

No equivalent exists for GRC evidence. When OSCAL records an observation about MFA enforcement, the `description` is free-text. When OpenControl documents how EC2 satisfies AC-2, it is a narrative string. There is no shared vocabulary, no attribute dictionary, no event class hierarchy for compliance evidence.

OCEAN fills this gap with its OCSF-inspired schema (Constitution Principle II):
```
Control Domain > Evidence Class > Attributes
```
- Shared attribute dictionary (timestamp, resource_id, status mean the same everywhere)
- Profile system for cross-cutting concerns
- Extension mechanism for regulation-specific evidence
- Enum-first approach for classification

### 5.3 OCEAN's Unique Position

OCEAN sits in a specific, unoccupied position in the GRC tooling landscape:

```
                    CONTROL DEFINITION          EVIDENCE COLLECTION
                    (What to check)             (How to prove it)

CCM ................[X]...........................[ ]
OSCAL ..............[X]...........................[ ] (href only)
OpenControl ........[X]...........................[ ] (file path only)

                    THREAT TAXONOMY             BEHAVIORAL TESTING
                    (What to test for)          (How to test safely)

ATT&CK ............[X]...........................[ ]

                    EVIDENCE SCHEMA +           ACTIVE VERIFICATION +
                    NORMALIZATION               SAFETY SEMANTICS

OCEAN ..............[ ] (consumes catalogs)......[X] <-- UNIQUE VALUE
```

OCEAN is NOT a control catalog (it consumes OSCAL, CCM, etc.). OCEAN is the evidence acquisition and verification layer -- it takes control requirements from catalogs and produces structured, normalized, provenance-tracked evidence proving whether those controls are operating effectively.

---

## 6. Design Implications for OCEAN

### 6.1 Borrow From ATT&CK's Taxonomy Design

ATT&CK's ID format and hierarchy is the best model for OCEAN's evidence class taxonomy:

```
OCEAN Evidence Taxonomy (inspired by ATT&CK structure):
  Domain:  OD-XXX  (e.g., OD-001 = Identity & Access Management)
  Class:   OC-XXXX (e.g., OC-1001 = MFA Policy Configuration)
  Subclass: OC-XXXX.YYY (e.g., OC-1001.001 = Okta MFA Policy)
```

Key patterns to adopt:
- Self-documenting hierarchical IDs with dot notation for subclasses
- Stable parents, evolving children
- Rich metadata per node (source system, collection method, evidence type)
- Flat objects with typed relationships (not deep nesting)

### 6.2 Interoperate With OSCAL

OCEAN should be able to:
1. **Import** OSCAL catalogs/profiles as control definitions
2. **Export** evidence as OSCAL-compatible observations with `relevant-evidence` links
3. **Generate** OSCAL assessment results from OCEAN evaluation results
4. **Map** OCEAN evidence classes to OSCAL control objectives via `target.target-id`

The mapping layer: OCEAN evidence --> OSCAL observation + finding

### 6.3 Adopt CCM's Framework Mapping Pattern

CCM's framework mapping approach (control-to-control cross-reference table) should be adopted for OCEAN's control mapping:

```yaml
framework_mappings:
  - ocean_control: "IAM.MFA_ENFORCEMENT"
    mappings:
      - framework: "NIST-800-53"
        controls: ["IA-2(1)", "IA-2(2)"]
      - framework: "SOC2-CC"
        controls: ["CC6.1"]
      - framework: "ISO-27001"
        controls: ["A.9.4.2"]
      - framework: "CSA-CCM"
        controls: ["IAM-02", "IAM-04"]
```

### 6.4 Fill OpenControl's Evidence Gap

OpenControl had the right idea (compliance as code) but the wrong execution (narratives instead of evidence). OCEAN should be what OpenControl would have been if it had:
- Structured evidence schemas instead of text narratives
- Automated collection instead of manual YAML authoring
- Evaluation logic instead of manually-set status enums
- Temporal tracking instead of point-in-time snapshots

---

## Evidence Trail & Citations

### Primary Sources Consulted

1. NIST OSCAL Official Documentation - https://pages.nist.gov/OSCAL/
2. NIST OSCAL Layers and Models - https://pages.nist.gov/OSCAL/learn/concepts/layer/
3. OSCAL Assessment Results Model v1.1.2 JSON Reference - https://pages.nist.gov/OSCAL-Reference/models/v1.1.2/assessment-results/json-reference/
4. OSCAL Assessment Results JSON Definitions - https://pages.nist.gov/OSCAL-Reference/models/v1.1.2/assessment-results/json-definitions/
5. OSCAL GitHub Repository - https://github.com/usnistgov/OSCAL
6. FedRAMP OSCAL Automation - https://automate.fedramp.gov/
7. OpenControl Schemas Repository - https://github.com/opencontrol/schemas
8. OpenControl Schemas README - https://github.com/opencontrol/schemas/blob/master/README.md
9. OpenControl Philosophy - https://open-control.org/philosophy/
10. OpenControl cf-compliance Example - https://github.com/opencontrol/cf-compliance/blob/master/BOSH/component.yaml
11. MITRE ATT&CK Official Site - https://attack.mitre.org/
12. MITRE ATT&CK STIX Data Repository - https://github.com/mitre-attack/attack-stix-data
13. MITRE ATT&CK Data Model - https://mitre-attack.github.io/attack-data-model/
14. MITRE ATT&CK FAQ - https://attack.mitre.org/resources/faq/
15. MITRE ATT&CK Techniques (Enterprise) - https://attack.mitre.org/techniques/enterprise/
16. MITRE CTI Repository - https://github.com/mitre/cti
17. CSA Cloud Controls Matrix - https://cloudsecurityalliance.org/research/cloud-controls-matrix
18. CSA CCM v4.1 Artifacts - https://cloudsecurityalliance.org/artifacts/cloud-controls-matrix-v4-1
19. CSA CCM v4 Blog Announcement - https://cloudsecurityalliance.org/blog/2020/10/16/what-is-the-cloud-controls-matrix-ccm
20. Paramify: Benefits and Shortcomings of OSCAL - https://www.paramify.com/blog/the-benefits-and-shortcomings-of-oscal
21. Schellman: CSA CCM v3 vs v4 - https://www.schellman.com/blog/cloud-compliance/csa-ccm-v3-01-vs-v4
22. ATT&CK Sub-Techniques Blog - https://medium.com/mitre-attack/attack-with-sub-techniques-is-now-just-attack-8fc20997d8de
