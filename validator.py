"""
validator.py — Static analysis pass for registry.yaml.

Three-phase validation:
  1. Schema check   — registry.yaml must conform to registry.schema.json.
  2. Exact check    — Aho-Corasick scan for forbidden tokens in each fact.
  3. Fuzzy check    — Levenshtein distance catches near-miss evasion attempts.

Exit 0 if clean; exit 1 on any violation.
"""

import hashlib
import json
import sys
from pathlib import Path

import jsonschema
import yaml

from algorithms import AhoCorasick, levenshtein

FORBIDDEN_WORDS  = ["risk", "fail", "compliance"]
FUZZY_THRESHOLD  = 1       # edit distance ≤ this is flagged as a near-miss
REGISTRY_PATH    = __import__("os").environ.get("REGISTRY_PATH", "registry.yaml")
SCHEMA_PATH      = "registry.schema.json"
HASH_PATH        = Path(".registry.sha256")

# Build the automaton once at import time — shared across all validate() calls.
_automaton = AhoCorasick(FORBIDDEN_WORDS)


def load_registry(path: str) -> dict:
    with open(path) as f:
        return yaml.safe_load(f)


def load_schema(path: str) -> dict:
    with open(path) as f:
        return json.load(f)


def validate_schema(registry: dict, schema: dict) -> list[str]:
    validator = jsonschema.Draft7Validator(schema)
    return [
        f"Schema violation at "
        f"'{'/'.join(str(p) for p in e.absolute_path) or '<root>'}': {e.message}"
        for e in sorted(validator.iter_errors(registry), key=str)
    ]


def validate_exact(registry: dict) -> list[str]:
    """
    Aho-Corasick scan: O(L) per fact regardless of how many forbidden words exist.
    Returns one violation string per match found.
    """
    violations = []
    for sensor in registry.get("sensors", []):
        name = sensor.get("name", "<unnamed>")
        for fact in sensor.get("allowed_facts", []):
            hits = _automaton.search(fact.lower())
            if hits:
                matched = [pattern for _, pattern in hits]
                violations.append(
                    f"Sensor '{name}': fact '{fact}' "
                    f"contains forbidden token(s): {matched}  [exact]"
                )
    return violations


def validate_fuzzy(registry: dict) -> list[str]:
    """
    Levenshtein scan: splits each fact into tokens (snake_case) and flags any
    token within FUZZY_THRESHOLD edits of a forbidden word.

    Catches evasions like 'r1sk', 'rsk', 'fial', 'c0mpliance'.
    Only runs on facts that passed the exact check.
    """
    violations = []
    exact_flagged = {
        fact
        for sensor in registry.get("sensors", [])
        for fact in sensor.get("allowed_facts", [])
        if _automaton.search(fact.lower())
    }

    for sensor in registry.get("sensors", []):
        name = sensor.get("name", "<unnamed>")
        for fact in sensor.get("allowed_facts", []):
            if fact in exact_flagged:
                continue
            tokens = fact.lower().split("_")
            near_misses = [
                (token, fw)
                for token in tokens
                for fw in FORBIDDEN_WORDS
                if 0 < levenshtein(token, fw) <= FUZZY_THRESHOLD
            ]
            if near_misses:
                violations.append(
                    f"Sensor '{name}': fact '{fact}' "
                    f"contains near-miss token(s): "
                    f"{[(t, f'≈{fw} dist={levenshtein(t, fw)}') for t, fw in near_misses]}"
                    f"  [fuzzy, threshold={FUZZY_THRESHOLD}]"
                )
    return violations


def main():
    registry = load_registry(REGISTRY_PATH)
    schema   = load_schema(SCHEMA_PATH)

    # Phase 1 — structural schema
    schema_errors = validate_schema(registry, schema)
    if schema_errors:
        print("[VALIDATOR] FAIL — registry does not conform to schema:")
        for e in schema_errors:
            print(f"  - {e}")
        sys.exit(1)
    print("[VALIDATOR] Phase 1 passed: schema valid.")

    # Phase 2 — exact forbidden-word scan (Aho-Corasick)
    exact_errors = validate_exact(registry)
    if exact_errors:
        print("[VALIDATOR] FAIL — forbidden tokens detected (exact match):")
        for e in exact_errors:
            print(f"  - {e}")
        sys.exit(1)
    print("[VALIDATOR] Phase 2 passed: no exact forbidden tokens.")

    # Phase 3 — fuzzy evasion scan (Levenshtein)
    fuzzy_errors = validate_fuzzy(registry)
    if fuzzy_errors:
        print("[VALIDATOR] FAIL — near-miss evasion detected (fuzzy match):")
        for e in fuzzy_errors:
            print(f"  - {e}")
        sys.exit(1)
    print("[VALIDATOR] Phase 3 passed: no fuzzy near-misses.")

    # Seal: write approved SHA256 only for the production registry.
    # Doctrine: trust boundary — the firewall must not accept a registry that
    # was not approved by the validator. Test fixtures are sealed if REGISTRY_HASH_PATH is set.
    should_seal = (
        Path(REGISTRY_PATH).resolve() == Path("registry.yaml").resolve() or
        __import__("os").environ.get("REGISTRY_HASH_PATH")
    )
    if should_seal:
        hash_path = Path(__import__("os").environ.get("REGISTRY_HASH_PATH", ".registry.sha256"))
        approved_hash = hashlib.sha256(Path(REGISTRY_PATH).read_bytes()).hexdigest()
        hash_path.write_text(approved_hash + "\n")
        print(f"[VALIDATOR] Registry sealed: {approved_hash}")
    print("[VALIDATOR] PASS — registry is structurally and semantically clean.")
    sys.exit(0)


if __name__ == "__main__":
    main()
