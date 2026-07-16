"""
Event ingestion for mini-siem.

Reads JSON-lines log events, either from a static file (batch/demo mode)
or by tailing a file as it grows (like a real log forwarder would). Each
event is expected to look like:

    {"ts": 1721040000, "event_type": "auth_failure", "src_ip": "10.0.0.5", "user": "root"}

Extend this to parse real log formats (syslog, auth.log, Windows Event
Log XML, CloudTrail JSON, etc.) and normalize them into this event shape —
that normalization step is most of what real SIEM ingest pipelines do.
"""

import json
import time
from typing import Generator, Dict, Any


def read_events_from_file(path: str) -> Generator[Dict[str, Any], None, None]:
    """Batch mode: read all events from a file at once (for demos/tests)."""
    with open(path, "r") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            yield json.loads(line)


def tail_events(path: str, poll_interval: float = 1.0) -> Generator[Dict[str, Any], None, None]:
    """Stream mode: tail a file for new lines, like `tail -f`, so this can
    sit behind a real log source that's actively being appended to."""
    with open(path, "r") as f:
        f.seek(0, 2)  # seek to end
        while True:
            line = f.readline()
            if not line:
                time.sleep(poll_interval)
                continue
            line = line.strip()
            if line:
                try:
                    yield json.loads(line)
                except json.JSONDecodeError:
                    continue
