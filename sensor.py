"""
sensor.py — Base class for all sensors.

Subclass Sensor and call self.emit(fact, value).
The firewall is enforced automatically; sensors never touch it directly.
"""

import firewall


class Sensor:
    def __init__(self, name: str):
        self.name = name

    def emit(self, fact: str, value) -> None:
        firewall.emit(self.name, fact, value)
