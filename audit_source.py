"""
audit_source.py — AuditSource base class.

An AuditSource is a named origin of audit facts (e.g. access_control,
financial_ledger). It wraps Sensor so the firewall contract is enforced
automatically on every emit.

Subclass it and call self.emit(fact, value) to publish a single audit fact.
The fact must be declared in registry.yaml for this source — otherwise the
firewall raises ValueError before anything is written.
"""

from sensor import Sensor


class AuditSource(Sensor):
    """
    Thin subclass of Sensor with audit-domain semantics.
    The name must match an entry in registry.yaml.
    """

    def emit(self, fact: str, value) -> None:
        """
        Publish one audit fact.

        Args:
            fact:  The fact key (must be in this source's allowed_facts).
            value: The raw observed value — no interpretation, no scoring.
        """
        super().emit(fact, value)
