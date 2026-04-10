"""
test_scenario.py — Audit-domain scenarios for the semantic firewall harness.

Scenarios:
  1. Static validator rejects a registry with forbidden words.
  2. Runtime firewall blocks an undeclared fact.
  3. Compliant audit sources emit declared facts cleanly.
  4. Levenshtein fuzzy scan catches near-miss evasion.
  5. Registry tamper detection — firewall denies all emissions if registry
     is modified after validation (integrity chain).
"""

import sys
import shutil
from pathlib import Path

import firewall
from harness import Harness

h = Harness()

# ── Scenario 1: static validator rejects forbidden words ─────────────────────
h.should_fail_validation(
    registry_path="test_fixtures/bad_registry.yaml",
    label="validator rejects 'bad_auditor' (interpretive fields contain forbidden tokens)",
)

# ── Scenario 2: runtime firewall blocks an undeclared fact ───────────────────
h.should_block(
    sensor="access_control",
    fact="verdict",
    value="suspicious",
    label="access_control blocked on undeclared interpretive field 'verdict'",
)

# ── Scenario 3: compliant audit sources pass through ─────────────────────────
h.should_pass("access_control",   "user_id",        "u-8821",                           label="access_control logs user_id")
h.should_pass("access_control",   "resource_id",    "res-policy-42",                    label="access_control logs resource_id")
h.should_pass("access_control",   "action",         "read",                             label="access_control logs action")
h.should_pass("access_control",   "timestamp",      "2026-04-10T09:15:00Z",             label="access_control logs timestamp")
h.should_pass("financial_ledger", "transaction_id", "txn-00441",                        label="financial_ledger logs transaction_id")
h.should_pass("financial_ledger", "amount_usd",     4250.00,                            label="financial_ledger logs amount_usd")
h.should_pass("financial_ledger", "entry_type",     "debit",                            label="financial_ledger logs entry_type")
h.should_pass("system_integrity", "file_path",      "/etc/passwd",                      label="system_integrity logs file_path")
h.should_pass("system_integrity", "checksum",       "d41d8cd98f00b204e9800998ecf8427e", label="system_integrity logs checksum")
h.should_pass("system_integrity", "event_type",     "read",                             label="system_integrity logs event_type")

# ── Scenario 4: Levenshtein catches near-miss evasion ────────────────────────
h.should_flag_fuzzy(
    registry={
        "sensors": [{
            "name": "evasion_sensor",
            "allowed_facts": ["r1sk_score", "fial_count"]
        }]
    },
    label="fuzzy scan catches 'r1sk_score' as near-miss evasion of 'risk' (dist=1)",
)

# ── Scenario 5: registry tamper detection ────────────────────────────────────
# Corrupt the registry on disk after validation, then attempt an emission.
# The firewall must detect the hash mismatch and raise RuntimeError.
REGISTRY = Path("registry.yaml")
BACKUP   = Path("registry.yaml.bak")

def tamper_and_emit():
    shutil.copy(REGISTRY, BACKUP)
    try:
        original = REGISTRY.read_text()
        REGISTRY.write_text(original + "\n# tampered\n")
        firewall.emit("access_control", "user_id", "u-9999")
    finally:
        shutil.copy(BACKUP, REGISTRY)
        BACKUP.unlink(missing_ok=True)

h.should_raise(
    exc_type=RuntimeError,
    fn=tamper_and_emit,
    label="firewall detects registry tampered post-validation and denies emission",
)

h.run()
h.report()
sys.exit(h.exit_code())
