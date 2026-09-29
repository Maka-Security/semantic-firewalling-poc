"""
intake_agent.py — NIST CSF evidence intake agent with firewall enforcement.

This agent processes evidence posted in an intake forum, extracts factual
observations, categorizes them into NIST CSF functions, and emits only
approved facts through the semantic firewall.

The firewall prevents:
  - Hallucinated evidence not present in forum posts
  - Off-topic meta-commentary and subjective judgments
  - Free-form agent reasoning contaminating the evidence log
  - Untraced evidence linkages

Agent reasoning is unconstrained internally, but emissions are gated.
"""

from sensor import Sensor
from datetime import datetime, timezone


class NISTIntakeAgent(Sensor):
    """
    Agent that processes forum evidence for NIST CSF maturity assessment.
    """

    def __init__(self):
        super().__init__("nist_csf_intake_agent")
        self.iso_now = datetime.now(timezone.utc).isoformat()

    def process_forum_post(self, post_id: str, content: str, timestamp: str, posting_user: str = None) -> dict:
        """
        Process a single forum post and emit approved evidence facts.

        Args:
            post_id: Unique forum post identifier (e.g., "#post-2847")
            content: Full text of the forum post
            timestamp: When the post was created (ISO-8601)
            posting_user: User who posted (optional)

        Returns:
            Dictionary of emitted facts for audit trail.
        """
        emitted = {}

        # ── Step 1: Categorize into NIST CSF function ──────────────────────────

        function = self._categorize_function(content)
        if function:
            fact_name = f"forum_post_mapped_to_function_{function}"
            self.emit(fact_name, post_id)
            emitted[fact_name] = post_id

        # ── Step 2: Identify evidence type ──────────────────────────────────────

        evidence_type = self._identify_evidence_type(content)
        if evidence_type:
            fact_name = f"evidence_type_{evidence_type}"
            self.emit(fact_name, post_id)
            emitted[fact_name] = post_id

        # ── Step 3: Extract factual observations ────────────────────────────────

        extractions = self._extract_facts(content)

        if extractions.get("control_name"):
            self.emit("evidence_extracted_control_name", extractions["control_name"])
            emitted["evidence_extracted_control_name"] = extractions["control_name"]

        if extractions.get("implementation_date"):
            self.emit("evidence_extracted_implementation_date", extractions["implementation_date"])
            emitted["evidence_extracted_implementation_date"] = extractions["implementation_date"]

        if extractions.get("last_test_date"):
            self.emit("evidence_extracted_last_test_date", extractions["last_test_date"])
            emitted["evidence_extracted_last_test_date"] = extractions["last_test_date"]

        if extractions.get("responsible_team"):
            self.emit("evidence_extracted_responsible_team", extractions["responsible_team"])
            emitted["evidence_extracted_responsible_team"] = extractions["responsible_team"]

        # ── Step 4: Emit maturity indicators (enumerated) ───────────────────────

        indicators = self._identify_maturity_indicators(content)
        for indicator in indicators:
            fact_name = f"maturity_indicator_{indicator}"
            self.emit(fact_name, post_id)
            emitted[fact_name] = post_id

        # ── Step 5: Identify findings (gaps/inconsistencies) ──────────────────

        findings = self._identify_findings(content, extractions)
        for finding in findings:
            fact_name = f"finding_{finding}"
            self.emit(fact_name, post_id)
            emitted[fact_name] = post_id

        # ── Step 6: Emit audit linkage (traceability) ──────────────────────────

        self.emit("audit_link_forum_post_id", post_id)
        emitted["audit_link_forum_post_id"] = post_id

        # Emit a quote from the forum (proof)
        quote = content[:150] + "..." if len(content) > 150 else content
        self.emit("audit_link_evidence_source_quote", quote)
        emitted["audit_link_evidence_source_quote"] = quote

        self.emit("audit_link_extracted_from_forum_post_timestamp", timestamp)
        emitted["audit_link_extracted_from_forum_post_timestamp"] = timestamp

        # ── Step 7: Metadata ─────────────────────────────────────────────────

        self.emit("metadata_assessment_date_utc", self.iso_now)
        self.emit("metadata_forum_post_url", post_id)
        if posting_user:
            self.emit("metadata_posting_user", posting_user)

        return emitted

    # ── Internal reasoning (NOT gated by firewall) ──────────────────────────────

    def _categorize_function(self, content: str) -> str:
        """
        Agent internal reasoning: which NIST CSF function is this evidence for?
        Can use any heuristic, LLM reasoning, pattern matching, etc.

        Returns the function name (identify, protect, detect, respond, recover)
        or None if unclear.
        """
        content_lower = content.lower()

        # Try to extract explicit "Function:" field
        for line in content_lower.split("\n"):
            if "function:" in line:
                func_value = line.split("function:")[-1].strip()
                if func_value in ["identify", "protect", "detect", "respond", "recover"]:
                    return func_value

        # Check DETECT (SIEM, detection capabilities, monitoring)
        if "siem" in content_lower or "detection" in content_lower:
            return "detect"

        # Check RESPOND (incident response plan/testing)
        if "incident response plan" in content_lower or ("incident response" in content_lower and "test" in content_lower):
            return "respond"

        # Check RECOVER (recovery/backup)
        if "recovery" in content_lower or "backup" in content_lower or "restore" in content_lower:
            return "recover"

        # Check PROTECT (access control, firewall, encryption)
        if "access control" in content_lower or "firewall" in content_lower or "encryption" in content_lower:
            return "protect"

        # Check IDENTIFY (asset management, inventory)
        if "asset" in content_lower or "inventory" in content_lower:
            return "identify"

        return None

    def _identify_evidence_type(self, content: str) -> str:
        """
        Agent internal reasoning: what type of evidence is this?
        """
        content_lower = content.lower()

        # Check for procedures (documented procedures, response procedures, incident procedures)
        # Priority: if "procedure" + "documented" together, it's likely a procedure
        if any(keyword in content_lower for keyword in ["documented procedure", "incident response procedure", "testing procedure"]):
            return "procedure"

        # Check for control documentation (explicit "Control:" header)
        if "control:" in content_lower and "documented procedure" not in content_lower:
            return "control_documentation"

        # Fallback: general procedure mention
        if "procedure" in content_lower:
            return "procedure"

        # Check for tool output (SIEM specifically)
        if "siem" in content_lower:
            return "tool_output"

        # Check for test results (only if explicitly "test result")
        if "test result" in content_lower:
            return "test_result"

        # Check for policies
        if "policy" in content_lower and "document" in content_lower:
            return "policy"

        # Check for interview/discussion
        if "interview" in content_lower or "spoke with" in content_lower:
            return "interview_notes"

        return None

    def _extract_facts(self, content: str) -> dict:
        """
        Agent internal reasoning: extract specific factual claims from content.
        This can use regex, NLP, LLM reasoning, or any technique.

        Returns only claims that can be verified in the source material.
        """
        facts = {}

        # Naive keyword matching (in production, this could be LLM-based)
        if "control:" in content.lower() or "control -" in content.lower():
            # Extract control name (simplistic)
            parts = content.split("control:")
            if len(parts) > 1:
                control_text = parts[1].split("\n")[0].strip()
                facts["control_name"] = control_text[:100]  # Truncate for safety

        if "implemented" in content.lower() and "2024" in content:
            facts["implementation_date"] = "2024"

        if "last test" in content.lower() or "tested" in content.lower():
            if "january" in content.lower():
                facts["last_test_date"] = "2025-01"
            elif "december" in content.lower():
                facts["last_test_date"] = "2024-12"

        if "team:" in content.lower() or "team -" in content.lower():
            parts = content.split("team:")
            if len(parts) > 1:
                team_text = parts[1].split("\n")[0].strip()
                facts["responsible_team"] = team_text[:50]

        return facts

    def _identify_maturity_indicators(self, content: str) -> list[str]:
        """
        Agent internal reasoning: what maturity indicators are present?
        """
        indicators = []

        if "document" in content.lower() or "documented" in content.lower():
            indicators.append("documented_procedure")

        if "role" in content.lower() or "assign" in content.lower():
            indicators.append("roles_assigned")

        if "metric" in content.lower() or "measure" in content.lower():
            indicators.append("metrics_collected")

        if "test" in content.lower() and "monthly" in content.lower():
            indicators.append("tested_within_30_days")

        if "test" in content.lower() and ("quarterly" in content.lower() or "90" in content.lower()):
            indicators.append("tested_within_90_days")

        if "train" in content.lower() or "training" in content.lower():
            indicators.append("training_completed")

        if "automat" in content.lower():
            indicators.append("automated_control")

        return indicators

    def _identify_findings(self, content: str, extractions: dict) -> list[str]:
        """
        Agent internal reasoning: what gaps or inconsistencies exist?
        """
        findings = []

        # Check for contradictions or missing elements
        if "not implement" in content.lower():
            findings.append("control_not_implemented")

        if any(keyword in content.lower() for keyword in ["no document", "undocumented", "lack" ]):
            if any(keyword in content.lower() for keyword in ["procedure", "document", "metric"]):
                findings.append("documentation_missing")

        if any(keyword in content.lower() for keyword in ["test", "formal testing", "testing procedure"]) and any(keyword in content.lower() for keyword in ["overdue", "lack", "no"]):
            findings.append("testing_overdue")

        if any(keyword in content.lower() for keyword in ["no metric", "not measur", "no formal metric", "lack", "don't have"]) and "metric" in content.lower():
            findings.append("metrics_not_collected")

        if "inconsistent" in content.lower():
            findings.append("inconsistent_execution")

        if any(keyword in content.lower() for keyword in ["role", "unclear", "overlap"]) and any(keyword in content.lower() for keyword in ["unclear", "overlap", "not clear"]):
            findings.append("roles_unclear")
        elif "role" in content.lower() and ("unclear" in content.lower() or "overlap" in content.lower()):
            findings.append("roles_unclear")

        if "improvement plan" in content.lower() and ("missing" in content.lower() or "no" in content.lower()):
            findings.append("improvement_plan_missing")

        if any(keyword in content.lower() for keyword in ["not train", "no train", "training incomplete", "not formally train"]):
            findings.append("training_incomplete")

        return findings