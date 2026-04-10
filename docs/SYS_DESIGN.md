# Semantic Firewall — System Design Specification

**Version:** 1.0  
**Project:** semanticfirewallingpof  
**Organisation:** Maka Security Solutions  
**Classification:** Internal Engineering

---

## 1. Purpose

This document defines the system design of the Semantic Firewall — a schema contract enforcement system for multi-collaborator repositories.

The system solves one problem: **data producers must only emit facts they have contractually declared, and those declarations must be free of interpretive language.**

It does not solve anomaly detection, payload inspection, or network-layer filtering. Those are out of scope.

---

## 2. System Boundary

### 2.1 In Scope

- Static validation of `registry.yaml` at development time
- Runtime enforcement of fact-key allowlists at emission time
- Registry integrity verification between validation and runtime
- Pre-commit and CI enforcement across collaborators
- Structured, persistent audit logging of every emission decision

### 2.2 Out of Scope

- Validation of fact *values* (only keys are governed)
- Transport security (TLS, encryption at rest)
- Authentication of callers to `emit()`
- Network-layer enforcement
- Distributed deployment or multi-node coordination

---

## 3. System Architecture

### 3.1 Component Map

```
┌─────────────────────────────────────────────────────────────────┐
│  DEVELOPMENT TIME                                               │
│                                                                 │
│   registry.yaml ──► validator.py ──► .registry.sha256          │
│        │                │                                       │
│        │           [3 phases]                                   │
│        │           1. JSON Schema                               │
│        │           2. Aho-Corasick exact scan                   │
│        │           3. Levenshtein fuzzy scan                    │
│        │                                                        │
│   hooks/pre-commit ──► blocks commit on violation              │
│   .github/workflows ──► blocks PR merge on violation           │
└─────────────────────────────────────────────────────────────────┘
                │
                ▼ registry.yaml + .registry.sha256 committed
┌─────────────────────────────────────────────────────────────────┐
│  RUNTIME                                                        │
│                                                                 │
│   AuditSource.emit(fact, value)                                 │
│        │                                                        │
│        ▼                                                        │
│   firewall.emit(sensor, fact, value)                            │
│        │                                                        │
│        ├── Gate 1: registry.yaml exists?          ──No──► RuntimeError
│        ├── Gate 2: .registry.sha256 exists?       ──No──► RuntimeError
│        ├── Gate 3: SHA256 matches?                ──No──► RuntimeError + log
│        ├── Gate 4: sensor in registry?            ──No──► KeyError + log
│        ├── Gate 5: fact in BloomFilter?           ──No──► ValueError + log
│        ├── Gate 6: fact in exact set?             ──No──► ValueError + log
│        └── ALLOW ──────────────────────────────────────► log + return
│                                                                 │
│   logger.emit_event() ──► logs/firewall.log (JSON lines)       │
└─────────────────────────────────────────────────────────────────┘
```

### 3.2 Component Inventory

| Component | File | Role | Phase |
|---|---|---|---|
| Registry | `registry.yaml` | Source of truth — sensor names and allowed fact keys | Static |
| Schema | `registry.schema.json` | JSON Schema Draft 7 structural contract | Static |
| Validator | `validator.py` | Three-phase static analysis; writes registry seal | Dev time |
| Algorithms | `algorithms.py` | Aho-Corasick, BloomFilter, Levenshtein primitives | Both |
| Firewall | `firewall.py` | Runtime gate — enforces allowlists per emission | Runtime |
| Logger | `logger.py` | Structured JSON audit log; node identity | Runtime |
| Sensor | `sensor.py` | Base class; routes `emit()` through firewall | Runtime |
| AuditSource | `audit_source.py` | Domain subclass of Sensor for audit sources | Runtime |
| Harness | `harness.py` | Scenario registration and execution for testing | Test |
| Pre-commit hook | `hooks/pre-commit` | Blocks commits with invalid registry | Dev time |
| CI pipeline | `.github/workflows/firewall.yml` | Blocks PR merge on any violation | CI |
| Makefile | `Makefile` | Unified local interface for all collaborators | Dev time |

---

## 4. Data Structures

### 4.1 Registry (`registry.yaml`)

```
registry
  └── sensors: list
        └── sensor
              ├── name: string         snake_case, unique
              └── allowed_facts: list
                    └── fact: string   snake_case, unique within sensor
```

**Constraints enforced by schema:**
- `sensors` array is required, minimum 1 item
- Each sensor must have `name` and `allowed_facts`; no extra keys
- `name` pattern: `^[a-z][a-z0-9_]*$`
- `allowed_facts` minimum 1 item, all items unique
- Fact key pattern: `^[a-z][a-z0-9_]*$`

### 4.2 Registry Seal (`.registry.sha256`)

Single line: hex-encoded SHA-256 digest of `registry.yaml` bytes, written by `validator.py` on clean exit.

```
<64 hex chars>\n
```

Purpose: establishes a trust boundary between static validation and runtime enforcement. The firewall treats the registry as untrusted until the seal is verified.

### 4.3 Audit Log Entry (`logs/firewall.log`)

One JSON object per line (JSON Lines format):

```json
{
  "timestamp": "2026-04-10T09:15:00.123456+00:00",
  "node_id":   "a3f2c1d4-...",
  "source":    "<sensor_name | firewall | system>",
  "event":     "<allowed | blocked | registry_tampered | registry_error>",
  "<key>":     "<value>"
}
```

**Event-specific fields:**

| Event | Additional Fields |
|---|---|
| `allowed` | `fact`, `value` |
| `blocked` | `fact`, `gate` (`bloom` or `exact`), `allowed` (sorted list) |
| `registry_tampered` | `approved_sha256`, `current_sha256` |
| `registry_error` | `reason` |

### 4.4 Node Identity (`node_id`)

UUID v4, generated on first run, persisted to `node_id` file. Stable across restarts. Included in every log entry. Regenerated only if the file is deleted.

---

## 5. Algorithms

### 5.1 Aho-Corasick (Validator Phase 2)

**Problem:** check each fact key for membership in a set of forbidden substrings.

**Naive cost:** O(F × P × L) — for each of F facts, check each of P patterns of length L.

**Aho-Corasick cost:** O(Σ|patterns| + F × L + M) — build automaton once, scan each fact in a single left-to-right pass, M = number of matches.

**Construction:**
1. Build a trie from all forbidden patterns (goto function)
2. Compute failure links via BFS — each failure link points to the longest proper suffix of the current state that is also a prefix of some pattern
3. Merge output sets along failure chains

**Search:** traverse the automaton left-to-right over the fact string. On no valid transition, follow failure links. Collect all pattern matches from the output function.

**Why it matters:** with 3 forbidden words the gain is modest. With a forbidden word list of hundreds of entries (organisation policy growth), the scan cost stays O(fact length) rather than growing with the number of patterns.

### 5.2 Levenshtein Distance (Validator Phase 3)

**Problem:** catch near-miss evasions (`r1sk_score`) that pass exact substring matching.

**Algorithm:** Wagner-Fischer dynamic programming.

For strings a and b, build a DP table where `dp[i][j]` = minimum edits to transform `a[:i]` into `b[:j]`.

```
dp[i][j] = min(
    dp[i-1][j]   + 1,              # deletion
    dp[i][j-1]   + 1,              # insertion
    dp[i-1][j-1] + (a[i] != b[j]) # substitution (0 if match)
)
```

**Space optimisation:** only the current and previous rows are kept — O(min(|a|, |b|)) space.

**Cost:** O(|a| × |b|) time.

**Application:** each fact is split into snake_case tokens. Each token is compared against every forbidden word. If the edit distance is within `FUZZY_THRESHOLD` (currently 1), the fact is flagged.

**Threshold = 1 catches:** single character substitutions (`r1sk`), single deletions (`rsk`), single insertions (`riisk`).

**Threshold = 1 does not catch:** transpositions (`riks`) — these cost 2 in standard Levenshtein. Damerau-Levenshtein would reduce transpositions to cost 1.

### 5.3 Bloom Filter (Firewall runtime)

**Problem:** at high emit() throughput, the exact set lookup involves a hash computation and possible cache miss into a heap-allocated dict. A Bloom filter provides a fast, cache-friendly pre-screen.

**Structure:** a bit array of `m` bits. `k` independent hash positions per item, derived from two base hashes (MD5, SHA-256) via double hashing: `h_i(x) = (h1(x) + i × h2(x)) mod m`.

**Optimal parameters** given capacity `n` and desired false-positive rate `p`:

```
m = ceil(-n × ln(p) / ln(2)²)   bits
k = round((m / n) × ln(2))      hash functions
```

At `error_rate = 0.001` and `n = 5` facts: m ≈ 72 bits, k ≈ 10.

**Guarantee:** no false negatives. If a fact was `add()`ed, `__contains__` always returns True.

**Trade-off:** false positive rate p — a non-member may appear present. Falls through to exact set check, which resolves it.

**Decision path:**
```
fact not in bloom  → fact is DEFINITELY absent → block immediately (no set lookup)
fact in bloom      → fact is PROBABLY present  → verify with exact set
fact in exact set  → ALLOW
fact not in set    → false positive resolved    → block
```

---

## 6. Trust Model

### 6.1 Trust Boundaries

```
[Collaborator] ──writes──► [registry.yaml]    UNTRUSTED input
                                │
                         [validator.py]        TRUST GATE (static)
                                │
                      [.registry.sha256]       TRUSTED artefact
                                │
                         [firewall.py]         TRUST GATE (runtime)
                                │
                         [emit() allowed]      TRUSTED emission
```

**Assumptions:**
- `validator.py` output is trusted — it is the authority
- `registry.yaml` at runtime is untrusted — it may have been modified after validation
- `.registry.sha256` is the trust token — its presence and content prove the validator approved the registry
- The filesystem hosting `.registry.sha256` is trusted — tamper resistance at the OS/FS level is out of scope

**What the seal does not protect against:**
- An attacker who can write both `registry.yaml` and `.registry.sha256`
- A compromised Python process that patches `firewall.py` at runtime

**What the seal does protect against:**
- Accidental or opportunistic modification of `registry.yaml` after validation
- A collaborator editing the registry directly without running the validator
- A CI environment where the registry was modified between the validate step and the test step

### 6.2 Forbidden Word Policy

The forbidden word set `{"risk", "fail", "compliance"}` encodes the principle that audit fact keys must be observational, not interpretive.

| Forbidden | Why |
|---|---|
| `risk` | implies scoring or judgement; not a raw observation |
| `fail` | implies a verdict; the raw observation is the event, not its outcome |
| `compliance` | implies regulatory mapping; belongs in downstream analysis, not the emission layer |

This set is a policy decision, not a technical one. It is configured in `validator.py:FORBIDDEN_WORDS` and should be reviewed and approved by the responsible engineering authority before any change.

---

## 7. Enforcement Chain

### 7.1 Development Time (collaborator local)

```
Edit registry.yaml
      │
      ▼
make seal
      │
      ├── validator.py Phase 1: JSON Schema check
      ├── validator.py Phase 2: Aho-Corasick exact scan
      ├── validator.py Phase 3: Levenshtein fuzzy scan
      │
      ├── FAIL ──► sys.exit(1), violations printed, .registry.sha256 NOT written
      └── PASS ──► .registry.sha256 written
            │
            ▼
git add registry.yaml .registry.sha256
git commit
      │
      ▼
hooks/pre-commit
      │
      ├── if registry.yaml not staged: skip
      ├── python validator.py
      │
      ├── FAIL ──► commit rejected
      └── PASS ──► git add .registry.sha256, commit proceeds
```

### 7.2 CI (pull request / push)

```
GitHub Actions: firewall.yml
      │
      ├── Step 1: pip install -r requirements.txt
      ├── Step 2: python validator.py          (must exit 0)
      ├── Step 3: python test_scenario.py      (must exit 0)
      └── Step 4: sha256sum verify             (committed seal must match registry)
```

Any step exiting non-zero blocks the branch from merging.

### 7.3 Runtime

Every call to `firewall.emit()` performs registry integrity verification before any allowlist logic. A tampered or unvalidated registry causes all emissions to fail with `RuntimeError`. The tamper event is logged before raising.

---

## 8. Failure Modes

| Failure | Firewall behaviour | Log event |
|---|---|---|
| `registry.yaml` missing | `RuntimeError` — all emissions denied | `registry_error` |
| `.registry.sha256` missing (validator not run) | `RuntimeError` — all emissions denied | `registry_error` |
| SHA256 mismatch (registry modified post-validation) | `RuntimeError` — all emissions denied | `registry_tampered` |
| `registry.yaml` unparseable YAML | `RuntimeError` — all emissions denied | `registry_error` |
| Sensor not in registry | `KeyError` | `registry_error` |
| Fact not in allowlist (bloom gate) | `ValueError` | `blocked` (gate=bloom) |
| Fact not in allowlist (exact gate) | `ValueError` | `blocked` (gate=exact) |
| Log file write failure | Event written to stderr; emission proceeds | — |

**Fail-safe principle:** any uncertainty about the registry state results in denial, not allowance. The system fails closed.

**Log write failure:** the only non-fatal failure. Emission is not blocked by a logging error — blocking on log failure would allow an attacker to deny service by filling the disk. The failure is written to stderr for operator visibility.

---

## 9. File Layout

```
.
├── registry.yaml               Production sensor contract
├── registry.schema.json        JSON Schema Draft 7 structural contract
├── .registry.sha256            Validator-approved SHA-256 seal (committed)
│
├── validator.py                Static analysis (3 phases)
├── firewall.py                 Runtime enforcement gate
├── logger.py                   Structured audit logger
├── sensor.py                   Base sensor class
├── audit_source.py             Audit-domain subclass
├── algorithms.py               Aho-Corasick, BloomFilter, Levenshtein
│
├── harness.py                  Scenario harness
├── test_scenario.py            Scenario declarations
├── test_fixtures/
│   └── bad_registry.yaml       Invalid registry fixture (not sealed)
│
├── hooks/
│   └── pre-commit              Git pre-commit enforcement hook
├── .github/
│   └── workflows/
│       └── firewall.yml        GitHub Actions CI pipeline
├── Makefile                    Local command interface
├── requirements.txt            Python dependencies
│
└── logs/
    └── firewall.log            Persistent structured audit log (JSON Lines)
```

---

## 10. Collaborator Workflow

### 10.1 First-time setup

```bash
pip install -r requirements.txt
make install-hooks
```

### 10.2 Adding a new sensor

1. Add the sensor entry to `registry.yaml`
2. `make seal` — validate and write the seal
3. `git add registry.yaml .registry.sha256`
4. `git commit` — pre-commit hook re-validates
5. Open PR — CI validates, runs harness, verifies seal

### 10.3 Adding a new fact to an existing sensor

Same as 10.2.

### 10.4 Adding a new forbidden word

1. Add the word to `FORBIDDEN_WORDS` in `validator.py`
2. `make ci` — verify no existing registry entries are now in violation
3. If violations exist, resolve them first, then add the forbidden word
4. Commit both `validator.py` and `registry.yaml` (and new seal) together

---

## 11. Performance Characteristics

| Operation | Time complexity | Notes |
|---|---|---|
| Validator Phase 1 (schema) | O(N) | N = total nodes in registry document |
| Validator Phase 2 (Aho-Corasick) | O(F × L + M) | F = facts, L = avg length, M = matches |
| Validator Phase 3 (Levenshtein) | O(F × T × P × L²) | T = tokens/fact, P = forbidden words, L = avg length |
| Bloom filter add | O(k) | k = hash count ≈ 10 |
| Bloom filter lookup | O(k) | |
| Exact set lookup | O(1) average | Python dict hash |
| SHA-256 registry verification | O(file size) | Once per emit() call |
| Log write | O(entry length) | Append to file |

**Bottleneck at scale:** SHA-256 recomputation of `registry.yaml` on every `emit()` call. For high-throughput scenarios, cache the verified registry in memory after first verification and re-verify only when the file's mtime changes.

---

*End of SYS_DESIGN.md — next: COMPONENT_SPEC.md*
