"""
harness.py — Semantic firewall test harness.

Usage:
    h = Harness()
    h.should_pass("temperature_sensor", "temperature_celsius", 22.5)
    h.should_block("temperature_sensor", "battery_voltage", 3.7)
    h.run()           # executes all registered scenarios
    sys.exit(h.exit_code())
"""

import subprocess
import sys
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any

import firewall
import validator


class Outcome(Enum):
    PASS = auto()
    FAIL = auto()


@dataclass
class ScenarioResult:
    label: str
    expected: str          # "pass" | "block" | "validator_fail"
    outcome: Outcome
    reason: str = ""


@dataclass
class Harness:
    _scenarios: list[dict] = field(default_factory=list, init=False, repr=False)
    _results: list[ScenarioResult] = field(default_factory=list, init=False, repr=False)

    # ── scenario registration ─────────────────────────────────────────────────

    def should_pass(self, sensor: str, fact: str, value: Any, label: str = "") -> None:
        """Register a scenario that must emit successfully."""
        self._scenarios.append({
            "kind": "pass",
            "sensor": sensor,
            "fact": fact,
            "value": value,
            "label": label or f"{sensor} emits '{fact}'",
        })

    def should_block(self, sensor: str, fact: str, value: Any, label: str = "") -> None:
        """Register a scenario where the firewall must raise ValueError."""
        self._scenarios.append({
            "kind": "block",
            "sensor": sensor,
            "fact": fact,
            "value": value,
            "label": label or f"{sensor} blocked on '{fact}'",
        })

    def should_fail_validation(self, registry_path: str = "registry.yaml",
                               script: str = "validator.py", label: str = "") -> None:
        """Register a scenario where validator.py must exit 1 for the given registry."""
        self._scenarios.append({
            "kind": "validator_fail",
            "script": script,
            "registry_path": registry_path,
            "label": label or f"{script} must exit 1 for {registry_path}",
        })

    def should_flag_fuzzy(self, registry: dict, label: str = "") -> None:
        """Register a scenario where validate_fuzzy() must return at least one hit."""
        self._scenarios.append({
            "kind": "fuzzy_fail",
            "registry": registry,
            "label": label or "fuzzy scan must detect near-miss forbidden tokens",
        })

    def should_raise(self, exc_type: type, fn, label: str = "") -> None:
        """Register a scenario where calling fn() must raise exc_type."""
        self._scenarios.append({
            "kind": "raises",
            "exc_type": exc_type,
            "fn": fn,
            "label": label or f"must raise {exc_type.__name__}",
        })

    # ── execution ─────────────────────────────────────────────────────────────

    def run(self) -> None:
        """Execute every registered scenario in order."""
        self._results.clear()
        for s in self._scenarios:
            if s["kind"] == "pass":
                self._results.append(self._run_pass(s))
            elif s["kind"] == "block":
                self._results.append(self._run_block(s))
            elif s["kind"] == "validator_fail":
                self._results.append(self._run_validator_fail(s))
            elif s["kind"] == "fuzzy_fail":
                self._results.append(self._run_fuzzy_fail(s))
            elif s["kind"] == "raises":
                self._results.append(self._run_raises(s))

    def _run_pass(self, s: dict) -> ScenarioResult:
        try:
            firewall.emit(s["sensor"], s["fact"], s["value"])
            return ScenarioResult(s["label"], "pass", Outcome.PASS)
        except Exception as e:
            return ScenarioResult(s["label"], "pass", Outcome.FAIL, str(e))

    def _run_block(self, s: dict) -> ScenarioResult:
        try:
            firewall.emit(s["sensor"], s["fact"], s["value"])
            return ScenarioResult(
                s["label"], "block", Outcome.FAIL,
                "emit succeeded — firewall did not block it"
            )
        except ValueError as e:
            return ScenarioResult(s["label"], "block", Outcome.PASS, str(e))
        except Exception as e:
            return ScenarioResult(
                s["label"], "block", Outcome.FAIL,
                f"unexpected {type(e).__name__}: {e}"
            )

    def _run_fuzzy_fail(self, s: dict) -> ScenarioResult:
        hits = validator.validate_fuzzy(s["registry"])
        if hits:
            return ScenarioResult(
                s["label"], "fuzzy_fail", Outcome.PASS,
                "\n".join(hits)
            )
        return ScenarioResult(
            s["label"], "fuzzy_fail", Outcome.FAIL,
            "fuzzy scan found no near-miss tokens — evasion went undetected"
        )

    def _run_raises(self, s: dict) -> ScenarioResult:
        try:
            s["fn"]()
            return ScenarioResult(
                s["label"], f"raises:{s['exc_type'].__name__}", Outcome.FAIL,
                f"no exception raised — expected {s['exc_type'].__name__}"
            )
        except s["exc_type"] as e:
            return ScenarioResult(
                s["label"], f"raises:{s['exc_type'].__name__}", Outcome.PASS, str(e)
            )
        except Exception as e:
            return ScenarioResult(
                s["label"], f"raises:{s['exc_type'].__name__}", Outcome.FAIL,
                f"wrong exception: {type(e).__name__}: {e}"
            )

    def _run_validator_fail(self, s: dict) -> ScenarioResult:
        env = {**__import__("os").environ, "REGISTRY_PATH": s.get("registry_path", "registry.yaml")}
        result = subprocess.run(
            [sys.executable, s["script"]],
            capture_output=True, text=True, env=env
        )
        if result.returncode == 1:
            return ScenarioResult(
                s["label"], "validator_fail", Outcome.PASS,
                result.stdout.strip()
            )
        return ScenarioResult(
            s["label"], "validator_fail", Outcome.FAIL,
            f"validator exited {result.returncode} — expected 1"
        )

    # ── reporting ─────────────────────────────────────────────────────────────

    def report(self) -> None:
        """Print a structured summary of all results."""
        if not self._results:
            print("[HARNESS] No results — call run() first.")
            return

        passed = [r for r in self._results if r.outcome == Outcome.PASS]
        failed = [r for r in self._results if r.outcome == Outcome.FAIL]

        print(f"\n{'━' * 60}")
        print(f"  HARNESS REPORT   {len(passed)}/{len(self._results)} passed")
        print(f"{'━' * 60}")

        for r in self._results:
            icon = "PASS" if r.outcome == Outcome.PASS else "FAIL"
            tag  = f"[expect:{r.expected}]"
            print(f"  [{icon}] {tag} {r.label}")
            if r.reason:
                # indent reason lines
                for line in r.reason.splitlines():
                    print(f"         {line}")

        print(f"{'━' * 60}")
        if failed:
            print(f"  {len(failed)} scenario(s) failed.")
        else:
            print("  All scenarios passed.")
        print(f"{'━' * 60}\n")

    def exit_code(self) -> int:
        """Return 0 if all passed, 1 if any failed."""
        return 0 if all(r.outcome == Outcome.PASS for r in self._results) else 1
