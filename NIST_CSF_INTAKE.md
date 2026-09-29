# NIST CSF Intake Agent with Semantic Firewall

## Overview

This branch extends the semantic firewall system to support **NIST CSF maturity rating for evidence gathered from forum posts**.

The system solves a critical problem: LLM agents gathering evidence for compliance assessments are prone to:
- **Hallucinating** facts not in the source material
- **Drifting off-topic** into meta-commentary and subjective judgments
- **Breaking evidence chains** by failing to link findings to sources
- **Inconsistent reasoning** across runs

The semantic firewall prevents all of these by **gating the agent's emissions**.

## Architecture

```
Forum Posts
    ↓
[NISTIntakeAgent with Internal Reasoning (unconstrained)]
    ↓ (emissions gated)
[Semantic Firewall]
    ↓
Structured Evidence Log
    ↓
[Deterministic Rating Engine]
    ↓
Excel Sheet with NIST CSF Maturity Ratings + Audit Trail
```

## Files in This Branch

### Core Implementation

- **`nist_csf_registry.yaml`** — Registry of approved facts that the intake agent can emit
  - Evidence categorization (NIST CSF functions)
  - Evidence type identification (documentation, test result, policy, etc.)
  - Maturity indicators (enumerated observations only)
  - Finding categories (gaps/inconsistencies)
  - Audit linkage facts (traceability)
  - Metadata (timestamps, sources)
  - **Blocked**: subjective ratings, judgments, meta-commentary

- **`intake_agent.py`** — NIST CSF intake agent
  - Processes forum posts
  - Performs internal reasoning (unconstrained)
  - Emits only approved facts through firewall
  - Maintains audit linkage to source posts
  - Prevents hallucinations from leaking out

- **`test_fixtures/forum_posts.yaml`** — Realistic forum post samples
  - Control implementation updates
  - Test results
  - Assessment findings
  - Includes expected evidence types, maturity indicators, and findings

- **`test_intake_agent.py`** — Comprehensive test suite
  - Registry validation
  - Function categorization
  - Evidence type identification
  - Maturity indicator detection
  - Finding identification
  - Audit linkage verification
  - Firewall enforcement (blocks subjective facts)
  - Coverage verification (all facts in registry)

## Running the Tests

```bash
source venv/bin/activate
python3 test_intake_agent.py
```

Expected output:
```
======================================================================
  NIST CSF INTAKE AGENT TEST SUITE
======================================================================

✓ Registry validation passes
✓ Forum posts categorized to correct NIST CSF functions
✓ Evidence types identified correctly
✓ Maturity indicators identified correctly
✓ Findings identified correctly
✓ Audit linkage maintained for evidence traceability
✓ Firewall blocks subjective judgments
✓ Firewall blocks off-topic meta-commentary
✓ All emitted facts are in approved registry

======================================================================
  TEST RESULTS: 9 passed, 0 failed
======================================================================
```

## How It Works: Example

### Forum Post
```
Control: Access Control List Management
Function: PROTECT
Implementation Date: 2024-01
Last Test: 2025-01-15
Responsible Team: Identity & Access Team

We have documented procedures for all access control reviews.
Roles are clearly assigned to team members.
Testing happens monthly via automated scripts.
We collect metrics on access requests and denials.

Current gap: Need to formalize improvement plan for policy updates.
```

### Agent Processing (Internal)
The agent can reason however it wants:
- Parse the post
- Extract control names
- Infer function category
- Identify test frequency
- Spot gaps

### Agent Emissions (Gated by Firewall)
✅ **Allowed** (approved facts):
- `forum_post_mapped_to_function_protect` → "#post-2847"
- `evidence_type_control_documentation` → "#post-2847"
- `evidence_extracted_control_name` → "Access Control List Management"
- `evidence_extracted_implementation_date` → "2024-01"
- `evidence_extracted_last_test_date` → "2025-01-15"
- `maturity_indicator_documented_procedure` → "#post-2847"
- `maturity_indicator_roles_assigned` → "#post-2847"
- `maturity_indicator_tested_within_30_days` → "#post-2847"
- `finding_improvement_plan_missing` → "#post-2847"
- `audit_link_forum_post_id` → "#post-2847"
- `audit_link_evidence_source_quote` → "Control: Access Control List Management..."

❌ **Blocked** (would raise ValueError):
- `control_maturity_level` → 3 (too interpretive)
- `control_effectiveness` → "strong" (subjective)
- `risk_assessment` → "low" (prescriptive)
- `team_capability_assessment` → "high" (meta-commentary)

### Audit Trail (Excel Output)
```
Control Name            | Function  | Indicators          | Findings              | Forum Evidence | Last Test
────────────────────────┼───────────┼─────────────────────┼───────────────────────┼────────────────┼──────────
Access Control List Mgmt| PROTECT   | ✓ Documented        | Improvement plan      | #post-2847     | 2025-01-15
                        |           | ✓ Roles assigned    |   missing             |                |
                        |           | ✓ Metrics           |                       |                |
                        |           | ✓ Tested monthly    |                       |                |
```

## What's Next

### Phase 1: Rating Engine Integration
- Implement `rating_engine.py` — deterministic function that takes approved evidence facts and produces NIST CSF maturity levels (1-5)
- Scorecard: what evidence is required for each level
- Test with various evidence combinations

### Phase 2: Excel Export
- Implement `excel_export.py` — generate Excel sheet from:
  - Aggregated evidence facts
  - Computed maturity ratings
  - Audit linkage (forum post IDs)
  - Rollup by function (IDENTIFY, PROTECT, DETECT, RESPOND, RECOVER)

### Phase 3: Forum Integration
- Mock forum API to fetch posts
- Test with real forum post structure
- Implement post deduplication (don't reprocess old posts)

### Phase 4: Deployment
- Validate registry before production deployment
- Seal registry hash (`.registry.sha256`)
- Run production assessments
- Detect any tampered evidence

### Phase 5: Compliance & Audit
- Generate audit reports showing:
  - What was assessed and when
  - What evidence was used
  - How ratings were determined
  - Registry integrity proof

## Key Concepts

### Evidence Hierarchy
1. **Forum Post** (raw source)
2. **Extracted Facts** (agent reads, claims, verifies in source)
3. **Maturity Indicators** (enumerated observations)
4. **Findings** (gaps/inconsistencies)
5. **Audit Links** (proof: forum post ID + quote)
6. **Maturity Rating** (Level 1-5, derived from facts only)

### Firewall Enforcement
- **Schema**: Registry validates against `registry.schema.json`
- **Exact Match**: Facts must be in the approved list
- **Fuzzy Match**: Evasion attempts (near-miss words) are caught
- **Integrity Chain**: Registry hash proves nothing was modified post-validation

### Agent Constraints
The agent's **internal reasoning is unconstrained** (can use LLMs, heuristics, ML, etc.)
But its **emissions are gated** (must be in approved fact categories)

This separates:
- **What the agent thinks** (internal, unrestricted)
- **What the agent claims** (external, firewall-enforced)

## Testing Strategy

Current tests cover:
- ✓ Registry validation (schema, exact, fuzzy)
- ✓ Function categorization
- ✓ Evidence type identification
- ✓ Maturity indicator detection
- ✓ Finding identification
- ✓ Audit linkage
- ✓ Firewall enforcement
- ✓ Registry coverage

Upcoming tests:
- [ ] Rating engine determinism
- [ ] Excel export accuracy
- [ ] Forum API integration
- [ ] Post deduplication
- [ ] Tamper detection
- [ ] End-to-end assessment flow

## Design Decisions

### Why Gate at Emissions, Not Reasoning?
- Agent reasoning can be sophisticated (LLM, ML, heuristics)
- But output must be verifiable and constrained
- Separation of concerns: reasoning ≠ claims

### Why Enumerated Facts, Not Free-Form?
- Prevents hallucinations
- Enables deterministic rating logic
- Auditable and traceable
- No subjective interpretations

### Why Firewall, Not Just Validation?
- Validator checks static registry (pre-deployment)
- Firewall enforces at runtime (during assessment)
- Integrity chain detects tampering post-validation

## References

- Original firewall system: `firewall.py`, `validator.py`
- NIST CSF framework: https://www.nist.gov/cyberframework
- Maturity model concepts: ISO/IEC 15504, CMMI
