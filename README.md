# mini-siem

A minimal detection/correlation engine modeled on the rule format used by
real SIEMs: **Sigma** (the open, vendor-neutral rule standard adopted by
Elastic Security, Splunk, Microsoft Sentinel, and others). Rules are
declarative YAML; the engine matches a stream of structured events against
them, including time-windowed correlation rules like brute-force detection.

## What it does right now

- Loads Sigma-inspired YAML rules (`rules/brute_force.yml`)
- Matches events on field equality or `field|contains: value`
- Supports threshold/window correlation: "N matching events for the same
  group_by key within window_seconds" (e.g. 5 auth failures from the same
  IP within 60 seconds)
- Ingests events in batch mode (read a file) or stream mode (tail a
  growing file, like a real forwarder feeding it)

## Run the demo

```bash
pip install -r requirements.txt
python -m siem.main --rules rules/brute_force.yml --events demo_events.jsonl
```

You should see an alert fire on the 5th `auth_failure` event from
`203.0.113.5` (the brute-force rule), plus the sqlmap user-agent rule and
the suspicious sudo-parent rule.


