# CloudSOC

CloudSOC is a Mac-native SOC analyst dashboard built from scratch with Streamlit and SQLite. It accepts JSON, CSV, and text/syslog logs, normalizes them locally, runs deterministic detections, maps alerts to MITRE ATT&CK tactics, and supports lightweight incident triage.

## Run locally

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
streamlit run app.py
```

Open `http://localhost:8501`, load the sample dataset, and explore the dashboard. No cloud account, API key, Docker installation, or Windows tooling is required.

## Supported inputs

- JSON/JSONL events
- CSV exports
- Plain text and syslog-like logs

The project intentionally does not parse native Windows `.evtx` files. Export Windows events to JSON, CSV, or XML/text first, then upload them.

## Try it with sample data

Upload `sample_data/cloudsoc-demo-security-events.csv`, then choose **Run detection rules**. It produces authentication-failure, brute-force, successful-login-after-failures, suspicious-web-request, port-scan, and critical-event alerts.
