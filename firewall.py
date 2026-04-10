"""
firewall.py — Runtime semantic firewall for audit fact emission.

Doctrine applied (MAKA_SECURITY_PRINCIPLES, MAKA_THINKING_MODEL):

  Trust boundary: the registry is an external file — its integrity must be
  verified at runtime, not assumed. If the file has been modified since the
  validator approved it, all emissions are denied and the tampering is logged.

  Failure thinking: if the registry is missing or unparseable, the firewall
  fails safe — all emissions are denied. The failure is logged as a critical
  event. Silent failure is not permitted.

  Evidence integrity: every decision (allowed or blocked) is written to the
  persistent structured log via logger.emit_event().

Decision path for emit(sensor, fact, value):
  1. Load and integrity-check registry.yaml against .registry.sha256.
  2. Bloom filter pre-screen → fact definitely absent → blocked.
  3. Exact set check → confirms membership.
  4. Log decision and allow or raise ValueError.
"""

import hashlib
import yaml
from pathlib import Path

import logger
from algorithms import BloomFilter

REGISTRY_PATH  = Path("registry.yaml")
HASH_PATH      = Path(".registry.sha256")


# ── registry integrity ────────────────────────────────────────────────────────

def _registry_sha256() -> str:
    return hashlib.sha256(REGISTRY_PATH.read_bytes()).hexdigest()


def _verify_integrity() -> None:
    """
    Compare the current registry hash against the validator-approved hash.

    Raises RuntimeError if:
      - the registry file is missing
      - the approved hash file is missing (validator has not been run)
      - the hashes do not match (registry was modified post-validation)
    """
    if not REGISTRY_PATH.exists():
        logger.emit_event("firewall", "registry_error", {
            "reason": "registry.yaml not found"
        })
        raise RuntimeError("firewall: registry.yaml not found — all emissions denied")

    if not HASH_PATH.exists():
        logger.emit_event("firewall", "registry_error", {
            "reason": "no approved hash on record — run validator.py first"
        })
        raise RuntimeError("firewall: registry not validated — all emissions denied")

    approved = HASH_PATH.read_text().strip()
    current  = _registry_sha256()

    if current != approved:
        logger.emit_event("firewall", "registry_tampered", {
            "approved_sha256": approved,
            "current_sha256":  current,
        })
        raise RuntimeError("firewall: registry integrity check failed — all emissions denied")


# ── allowlist loading ─────────────────────────────────────────────────────────

def _load_allowlist(sensor_name: str) -> tuple[set[str], BloomFilter]:
    try:
        registry = yaml.safe_load(REGISTRY_PATH.read_bytes())
    except Exception as e:
        logger.emit_event("firewall", "registry_error", {"reason": str(e)})
        raise RuntimeError(f"firewall: failed to parse registry — {e}") from e

    for sensor in registry.get("sensors", []):
        if sensor.get("name") == sensor_name:
            facts = sensor.get("allowed_facts", [])
            exact = set(facts)
            bloom = BloomFilter(capacity=max(len(facts), 1), error_rate=0.001)
            for fact in facts:
                bloom.add(fact)
            return exact, bloom

    logger.emit_event("firewall", "registry_error", {
        "reason": f"sensor '{sensor_name}' not found in registry"
    })
    raise KeyError(f"sensor '{sensor_name}' not found in registry")


# ── public API ────────────────────────────────────────────────────────────────

def emit(sensor_name: str, fact: str, value) -> None:
    """
    Emit a single audit fact from a named sensor.

    Raises:
        RuntimeError — registry missing, unvalidated, or tampered
        KeyError     — sensor not registered
        ValueError   — fact not on the sensor's allowlist
    """
    # Gate 1: registry integrity
    _verify_integrity()

    # Gate 2: load allowlist
    exact, bloom = _load_allowlist(sensor_name)

    # Gate 3: bloom pre-screen
    if fact not in bloom:
        logger.emit_event(sensor_name, "blocked", {
            "fact":    fact,
            "gate":    "bloom",
            "allowed": sorted(exact),
        })
        raise ValueError(
            f"firewall blocked '{sensor_name}' emitting '{fact}' "
            f"(not in allowlist) — see logs/firewall.log"
        )

    # Gate 4: exact confirmation
    if fact not in exact:
        logger.emit_event(sensor_name, "blocked", {
            "fact":    fact,
            "gate":    "exact",
            "allowed": sorted(exact),
        })
        raise ValueError(
            f"firewall blocked '{sensor_name}' emitting '{fact}' "
            f"(bloom false positive resolved) — see logs/firewall.log"
        )

    # Allowed
    logger.emit_event(sensor_name, "allowed", {
        "fact":  fact,
        "value": value,
    })
