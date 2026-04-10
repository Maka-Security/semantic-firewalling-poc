"""
logger.py — Structured, persistent audit logger.

Maka doctrine requires all critical actions to produce logs that are:
  - timestamped
  - persistent
  - useful for incident investigation

Every emission decision (allowed or blocked) is written as a JSON line
to logs/firewall.log. stdout is also written for operator visibility.

Log format (one JSON object per line):
  {
    "timestamp": "<ISO-8601 UTC>",
    "node_id":   "<stable UUID>",
    "source":    "<sensor name | system>",
    "event":     "<allowed | blocked | registry_tampered | registry_error | ...>",
    ... event-specific fields ...
  }
"""

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path

LOG_PATH     = Path("logs/firewall.log")
NODE_ID_FILE = Path("node_id")


def _load_or_create_node_id() -> str:
    """
    Return a stable node identity.
    Generated once and persisted to disk. Does not change across restarts.
    """
    NODE_ID_FILE.parent.mkdir(parents=True, exist_ok=True)

    if NODE_ID_FILE.exists():
        try:
            content = NODE_ID_FILE.read_text().strip()
            uuid.UUID(content)   # validate format
            return content
        except (ValueError, OSError):
            pass

    node_id = str(uuid.uuid4())
    try:
        NODE_ID_FILE.write_text(node_id + "\n")
    except OSError as e:
        print(f"[LOGGER-WARN] could not persist node_id: {e}", flush=True)
    return node_id


_NODE_ID: str = _load_or_create_node_id()


def emit_event(source: str, event: str, data: dict) -> None:
    """
    Write a structured audit event to the persistent log and to stdout.

    Args:
        source: the sensor name or system component emitting the event
        event:  short event label (e.g. 'allowed', 'blocked', 'registry_error')
        data:   arbitrary key-value pairs specific to this event
    """
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "node_id":   _NODE_ID,
        "source":    source,
        "event":     event,
        **data,
    }

    line = json.dumps(entry)

    # Persistent log
    try:
        LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
        with LOG_PATH.open("a") as f:
            f.write(line + "\n")
    except OSError as e:
        # Log failure must itself be visible — write to stderr, never silently drop
        import sys
        print(f"[LOGGER-CRITICAL] log write failed: {e} | event={line}", file=sys.stderr, flush=True)

    # Operator stdout
    print(f"[{entry['event'].upper()}] {source} | {json.dumps(data)}")
