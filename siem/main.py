"""
mini-siem entry point.

Usage:
    python -m siem.main --rules rules/brute_force.yml --events demo_events.jsonl
    python -m siem.main --rules rules/brute_force.yml --tail live_events.jsonl
"""

import argparse
import json
import sys

from siem.engine import DetectionEngine, load_rules
from siem.ingest import read_events_from_file, tail_events


def main():
    parser = argparse.ArgumentParser(description="mini-siem: Sigma-style correlation engine")
    parser.add_argument("--rules", required=True, help="Path to YAML rule file")
    parser.add_argument("--events", help="Path to a JSONL event file (batch mode)")
    parser.add_argument("--tail", help="Path to a JSONL event file to tail (stream mode)")
    args = parser.parse_args()

    if not args.events and not args.tail:
        print("Provide either --events (batch) or --tail (stream)", file=sys.stderr)
        sys.exit(1)

    rules = load_rules(args.rules)
    print(f"Loaded {len(rules)} rules from {args.rules}")

    engine = DetectionEngine(rules)

    event_stream = read_events_from_file(args.events) if args.events else tail_events(args.tail)

    for event in event_stream:
        alerts = engine.process_event(event)
        for alert in alerts:
            print("[ALERT]", json.dumps(alert, default=str))


if __name__ == "__main__":
    main()
