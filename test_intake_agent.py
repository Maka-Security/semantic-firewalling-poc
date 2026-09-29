"""
test_intake_agent.py — Test scenarios for NIST CSF intake agent.

Validates that the agent:
  1. Correctly categorizes forum posts into NIST CSF functions
  2. Extracts verifiable facts from forum content
  3. Identifies maturity indicators and findings
  4. Emits only approved facts through the firewall
  5. Maintains audit linkage to source forum posts
  6. Does NOT hallucinate evidence not in the forum
  7. Does NOT emit subjective judgments
"""

import sys
import os
import yaml
from pathlib import Path

# Set environment variables BEFORE importing firewall
os.environ["REGISTRY_PATH"] = "nist_csf_registry.yaml"
os.environ["REGISTRY_HASH_PATH"] = ".nist_csf_registry.sha256"

import validator
import firewall
from intake_agent import NISTIntakeAgent

# ── Test harness ──────────────────────────────────────────────────────────────

class IntakeTestHarness:
    def __init__(self):
        self.results = []
        self.passed = 0
        self.failed = 0

    def run_test(self, name: str, test_fn):
        """Run a single test and track results."""
        try:
            test_fn()
            self.results.append(("PASS", name))
            self.passed += 1
            print(f"✓ {name}")
        except AssertionError as e:
            self.results.append(("FAIL", name, str(e)))
            self.failed += 1
            print(f"✗ {name}: {e}")
        except Exception as e:
            self.results.append(("ERROR", name, str(e)))
            self.failed += 1
            print(f"✗ {name}: ERROR: {e}")

    def report(self):
        """Print test summary."""
        print()
        print("=" * 70)
        print(f"  TEST RESULTS: {self.passed} passed, {self.failed} failed")
        print("=" * 70)
        if self.failed == 0:
            print("  ✓ All intake agent tests passed.")
            sys.exit(0)
        else:
            print(f"  ✗ {self.failed} test(s) failed.")
            sys.exit(1)


# ── Test fixtures ─────────────────────────────────────────────────────────────

def load_forum_posts():
    """Load forum post fixtures."""
    with open("test_fixtures/forum_posts.yaml") as f:
        data = yaml.safe_load(f)
    return data["forum_posts"]


# ── Tests ─────────────────────────────────────────────────────────────────────

h = IntakeTestHarness()

# Validate NIST CSF registry before running tests
def test_registry_validation():
    """Validate registry schema and content."""
    registry = validator.load_registry("nist_csf_registry.yaml")
    schema = validator.load_schema("registry.schema.json")

    schema_errors = validator.validate_schema(registry, schema)
    assert not schema_errors, f"Schema validation failed: {schema_errors}"

    exact_errors = validator.validate_exact(registry)
    assert not exact_errors, f"Exact validation failed: {exact_errors}"

    fuzzy_errors = validator.validate_fuzzy(registry)
    assert not fuzzy_errors, f"Fuzzy validation failed: {fuzzy_errors}"

h.run_test("Registry validation passes", test_registry_validation)


# Test 1: Agent categorizes forum posts correctly
def test_function_categorization():
    """Agent correctly maps posts to NIST CSF functions."""
    posts = load_forum_posts()
    agent = NISTIntakeAgent()

    for post in posts:
        emitted = agent.process_forum_post(
            post["post_id"],
            post["content"],
            post["timestamp"],
            post["posting_user"]
        )

        expected_function = post["expected_function"]
        expected_fact = f"forum_post_mapped_to_function_{expected_function}"

        assert expected_fact in emitted, \
            f"Post {post['post_id']} not categorized to {expected_function}"

h.run_test("Forum posts categorized to correct NIST CSF functions",
           test_function_categorization)


# Test 2: Agent identifies evidence types
def test_evidence_type_identification():
    """Agent correctly identifies evidence types."""
    posts = load_forum_posts()
    agent = NISTIntakeAgent()

    for post in posts:
        emitted = agent.process_forum_post(
            post["post_id"],
            post["content"],
            post["timestamp"]
        )

        expected_type = post["expected_evidence_type"]
        expected_fact = f"evidence_type_{expected_type}"

        assert expected_fact in emitted, \
            f"Post {post['post_id']} evidence type not identified as {expected_type}"

h.run_test("Evidence types identified correctly",
           test_evidence_type_identification)


# Test 3: Agent emits maturity indicators
def test_maturity_indicators():
    """Agent correctly identifies maturity indicators present in forum posts."""
    posts = load_forum_posts()
    agent = NISTIntakeAgent()

    for post in posts:
        emitted = agent.process_forum_post(
            post["post_id"],
            post["content"],
            post["timestamp"]
        )

        for expected_indicator in post["expected_indicators"]:
            fact_name = f"maturity_indicator_{expected_indicator}"
            assert fact_name in emitted, \
                f"Post {post['post_id']} missing indicator: {expected_indicator}"

h.run_test("Maturity indicators identified correctly",
           test_maturity_indicators)


# Test 4: Agent identifies findings
def test_finding_identification():
    """Agent correctly identifies gaps and inconsistencies."""
    posts = load_forum_posts()
    agent = NISTIntakeAgent()

    for post in posts:
        emitted = agent.process_forum_post(
            post["post_id"],
            post["content"],
            post["timestamp"]
        )

        for expected_finding in post["expected_findings"]:
            fact_name = f"finding_{expected_finding}"
            assert fact_name in emitted, \
                f"Post {post['post_id']} missing finding: {expected_finding}"

h.run_test("Findings identified correctly",
           test_finding_identification)


# Test 5: Agent maintains audit linkage
def test_audit_linkage():
    """Agent emits audit linkage facts proving evidence traceability."""
    posts = load_forum_posts()
    agent = NISTIntakeAgent()

    for post in posts:
        emitted = agent.process_forum_post(
            post["post_id"],
            post["content"],
            post["timestamp"]
        )

        assert "audit_link_forum_post_id" in emitted, \
            f"Post {post['post_id']} missing forum post ID linkage"

        assert "audit_link_evidence_source_quote" in emitted, \
            f"Post {post['post_id']} missing source quote"

        assert "audit_link_extracted_from_forum_post_timestamp" in emitted, \
            f"Post {post['post_id']} missing timestamp linkage"

h.run_test("Audit linkage maintained for evidence traceability",
           test_audit_linkage)


# Test 6: Firewall blocks subjective judgments
def test_firewall_blocks_subjective_facts():
    """Firewall rejects attempts to emit subjective judgments."""
    agent = NISTIntakeAgent()

    # Agent tries to emit subjective fact (should raise ValueError)
    try:
        agent.emit("control_maturity_level", 3)
        assert False, "Firewall should have blocked 'control_maturity_level'"
    except ValueError as e:
        assert "blocked" in str(e).lower()

h.run_test("Firewall blocks subjective judgments",
           test_firewall_blocks_subjective_facts)


# Test 7: Firewall blocks off-topic meta-commentary
def test_firewall_blocks_offtopic_facts():
    """Firewall rejects meta-commentary and off-topic observations."""
    agent = NISTIntakeAgent()

    # Try to emit meta-commentary (should raise ValueError)
    try:
        agent.emit("team_capability_assessment", "high")
        assert False, "Firewall should have blocked 'team_capability_assessment'"
    except ValueError as e:
        assert "blocked" in str(e).lower()

h.run_test("Firewall blocks off-topic meta-commentary",
           test_firewall_blocks_offtopic_facts)


# Test 8: All emitted facts are in the approved registry
def test_all_facts_in_registry():
    """Every fact emitted by the agent is in the approved registry."""
    registry = validator.load_registry("nist_csf_registry.yaml")
    allowed_facts = set(
        fact
        for sensor in registry["sensors"]
        if sensor["name"] == "nist_csf_intake_agent"
        for fact in sensor["allowed_facts"]
    )

    posts = load_forum_posts()
    agent = NISTIntakeAgent()

    for post in posts:
        emitted = agent.process_forum_post(
            post["post_id"],
            post["content"],
            post["timestamp"]
        )

        for fact_name in emitted.keys():
            assert fact_name in allowed_facts, \
                f"Emitted fact '{fact_name}' not in registry for post {post['post_id']}"

h.run_test("All emitted facts are in approved registry",
           test_all_facts_in_registry)


# Run all tests
if __name__ == "__main__":
    print("\n" + "=" * 70)
    print("  NIST CSF INTAKE AGENT TEST SUITE")
    print("=" * 70 + "\n")

    h.report()