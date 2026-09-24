"""SentinelDeck: a local-first SOC dashboard built from scratch for macOS."""
from __future__ import annotations

import json
import re
import sqlite3
from datetime import datetime, timedelta, timezone
from io import StringIO
from pathlib import Path
from typing import Any

import altair as alt
import pandas as pd
import streamlit as st

APP_DIR = Path(__file__).parent
DB_PATH = APP_DIR / "sentineldeck.db"

st.set_page_config(page_title="SentinelDeck", page_icon="🛡️", layout="wide")

st.markdown(
    """
    <style>
    .stApp { background: #08111d; color: #e9f2ff; }
    [data-testid="stSidebar"] { background: linear-gradient(180deg, #0d1d30 0%, #08111d 100%); border-right: 1px solid #1f3852; }
    [data-testid="stSidebar"] * { color: #dce9f8; }
    h1, h2, h3 { color: #f3f8ff !important; letter-spacing: -0.03em; }
    [data-testid="stMetric"] { background: #0e1b2b; border: 1px solid #203a55; border-radius: 14px; padding: 16px; }
    [data-testid="stMetricLabel"] { color: #98b1ca; }
    [data-testid="stMetricValue"] { color: #eaf7ff; }
    .stButton > button { border-radius: 9px; border: 1px solid #2d567b; background: #123b5c; color: #eff9ff; }
    .stButton > button:hover { border-color: #4ad2ff; color: #ffffff; background: #155278; }
    [data-testid="stDataFrame"] { border: 1px solid #203a55; border-radius: 10px; overflow: hidden; }
    div[data-baseweb="select"] > div, .stTextInput input, .stTextArea textarea { background: #0e1b2b !important; color: #eef7ff !important; border-color: #294865 !important; }
    .eyebrow { color: #4ad2ff; font-weight: 700; font-size: 0.76rem; letter-spacing: 0.12em; text-transform: uppercase; }
    .status-live { color: #78efb0; font-weight: 700; font-size: 0.8rem; }
    </style>
    """,
    unsafe_allow_html=True,
)


def connection() -> sqlite3.Connection:
    con = sqlite3.connect(DB_PATH, check_same_thread=False)
    con.row_factory = sqlite3.Row
    con.executescript(
        """
        CREATE TABLE IF NOT EXISTS events (
          id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT, host TEXT, user TEXT,
          source_ip TEXT, severity TEXT, event_type TEXT, message TEXT, raw TEXT
        );
        CREATE TABLE IF NOT EXISTS alerts (
          id INTEGER PRIMARY KEY AUTOINCREMENT, event_id INTEGER, title TEXT, severity TEXT,
          tactic TEXT, technique TEXT, evidence TEXT, status TEXT DEFAULT 'New',
          created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS incidents (
          id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT, severity TEXT, status TEXT,
          owner TEXT, notes TEXT, created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );
        """
    )
    return con


def query(sql: str, params: tuple = ()) -> pd.DataFrame:
    with connection() as con:
        return pd.read_sql_query(sql, con, params=params)


def severity_from(text: str) -> str:
    text = text.lower()
    if any(x in text for x in ["critical", "ransomware", "malware", "data exfiltration"]):
        return "Critical"
    if any(x in text for x in ["failed password", "failed login", "brute", "powershell", "suspicious"]):
        return "High"
    if any(x in text for x in ["warning", "scan", "denied", "unauthorized"]):
        return "Medium"
    return "Low"


def normalise(frame: pd.DataFrame) -> pd.DataFrame:
    aliases = {
        "timestamp": ["timestamp", "time", "datetime", "date"],
        "host": ["host", "hostname", "computer", "device"],
        "user": ["user", "username", "account"],
        "source_ip": ["source_ip", "src_ip", "ip", "client_ip"],
        "severity": ["severity", "level", "priority"],
        "event_type": ["event_type", "event", "type", "action"],
        "message": ["message", "description", "log", "raw"],
    }
    out = pd.DataFrame()
    lower = {str(c).lower(): c for c in frame.columns}
    for target, names in aliases.items():
        col = next((lower[n] for n in names if n in lower), None)
        out[target] = frame[col].astype(str) if col else ""
    out["timestamp"] = pd.to_datetime(out["timestamp"], errors="coerce", utc=True).fillna(pd.Timestamp.now(tz="UTC"))
    out["timestamp"] = out["timestamp"].dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    out["severity"] = out.apply(lambda row: row["severity"].title() if row["severity"].title() in {"Low", "Medium", "High", "Critical"} else severity_from(f"{row['event_type']} {row['message']}"), axis=1)
    out["host"] = out["host"].replace("", "unknown-host")
    out["event_type"] = out["event_type"].replace("", "log_event")
    out["raw"] = frame.astype(str).to_dict(orient="records")
    out["raw"] = out["raw"].map(json.dumps)
    return out


def parse_upload(uploaded: Any) -> pd.DataFrame:
    content = uploaded.getvalue().decode("utf-8", errors="replace")
    suffix = Path(uploaded.name).suffix.lower()
    if suffix == ".csv":
        return normalise(pd.read_csv(StringIO(content)))
    if suffix in {".json", ".jsonl", ".ndjson"}:
        rows = [json.loads(line) for line in content.splitlines() if line.strip()] if suffix != ".json" else json.loads(content)
        return normalise(pd.json_normalize(rows if isinstance(rows, list) else [rows]))
    ip = re.compile(r"(?:\d{1,3}\.){3}\d{1,3}")
    rows = []
    for line in content.splitlines():
        if line.strip():
            rows.append({"timestamp": "", "message": line, "source_ip": (ip.search(line).group(0) if ip.search(line) else ""), "event_type": "syslog"})
    return normalise(pd.DataFrame(rows))


def ingest(events: pd.DataFrame) -> int:
    columns = ["timestamp", "host", "user", "source_ip", "severity", "event_type", "message", "raw"]
    with connection() as con:
        con.executemany(
            "INSERT INTO events (timestamp,host,user,source_ip,severity,event_type,message,raw) VALUES (?,?,?,?,?,?,?,?)",
            [tuple(row[c] for c in columns) for _, row in events.iterrows()],
        )
    return len(events)


def run_detections() -> int:
    events = query("SELECT * FROM events ORDER BY timestamp")
    if events.empty:
        return 0
    created = 0
    seen = set(query("SELECT event_id, title FROM alerts").apply(lambda r: (r.event_id, r.title), axis=1).tolist())
    for _, event in events.iterrows():
        message = str(event.message).lower()
        detections: list[tuple[str, str, str, str]] = []
        if "failed" in message and any(x in message for x in ["login", "password", "logon", "ssh"]):
            detections.append(("Authentication failure", "High", "Credential Access", "T1110 Brute Force"))
        if "powershell" in message or "encodedcommand" in message:
            detections.append(("Suspicious command execution", "High", "Execution", "T1059 Command and Scripting Interpreter"))
        if any(x in message for x in ["port scan", "nmap", "scan detected"]):
            detections.append(("Network reconnaissance", "Medium", "Reconnaissance", "T1595 Active Scanning"))
        if event.severity == "Critical":
            detections.append(("Critical security event", "Critical", "Impact", "T1486 Data Encrypted for Impact"))
        for title, severity, tactic, technique in detections:
            if (event.id, title) not in seen:
                with connection() as con:
                    con.execute("INSERT INTO alerts (event_id,title,severity,tactic,technique,evidence) VALUES (?,?,?,?,?,?)", (event.id, title, severity, tactic, technique, event.message))
                created += 1
    return created


def load_demo() -> None:
    now = datetime.now(timezone.utc)
    demo = []
    for i in range(6):
        demo.append({"timestamp": (now - timedelta(minutes=i * 3)).isoformat(), "host": "macbook-sales", "user": "unknown", "source_ip": "203.0.113.45", "event_type": "ssh", "message": "Failed password for admin from 203.0.113.45", "severity": "High"})
    demo += [
        {"timestamp": now.isoformat(), "host": "api-prod", "user": "deploy", "source_ip": "198.51.100.20", "event_type": "web", "message": "Suspicious request: /../.env", "severity": "High"},
        {"timestamp": now.isoformat(), "host": "edge-fw", "user": "", "source_ip": "192.0.2.99", "event_type": "network", "message": "Nmap port scan detected", "severity": "Medium"},
        {"timestamp": now.isoformat(), "host": "fileserver", "user": "finance", "source_ip": "10.10.1.5", "event_type": "endpoint", "message": "Critical ransomware behavior detected", "severity": "Critical"},
    ]
    ingest(normalise(pd.DataFrame(demo)))


def metric_card(label: str, value: int, delta: str | None = None) -> None:
    st.metric(label, value, delta=delta)


with st.sidebar:
    st.title("🛡️ SentinelDeck")
    st.caption("Local-first SOC analyst workspace")
    st.markdown("<span class='status-live'>● LOCAL SENSOR ONLINE</span>", unsafe_allow_html=True)
    page = st.radio("Workspace", ["Overview", "Ingest logs", "Alert queue", "Incidents", "MITRE coverage", "Reports"])
    st.divider()
    if st.button("Load safe demo activity", use_container_width=True):
        load_demo()
        st.success("Demo events added.")
    if st.button("Reset local data", use_container_width=True):
        with connection() as con:
            con.executescript("DELETE FROM alerts; DELETE FROM incidents; DELETE FROM events;")
        st.rerun()

events = query("SELECT * FROM events ORDER BY timestamp DESC")
alerts = query("SELECT * FROM alerts ORDER BY created_at DESC")

if page == "Overview":
    st.markdown("<div class='eyebrow'>SOC command center</div>", unsafe_allow_html=True)
    st.title("Security overview")
    st.caption("A focused view of locally ingested security telemetry. Your logs remain on this Mac.")
    a, b, c, d = st.columns(4)
    with a: metric_card("Events", len(events))
    with b: metric_card("Open alerts", len(alerts[alerts.status != "Resolved"]) if not alerts.empty else 0)
    with c: metric_card("Critical", int((alerts.severity == "Critical").sum()) if not alerts.empty else 0)
    with d: metric_card("Hosts", events.host.nunique() if not events.empty else 0)
    if events.empty:
        st.info("Start with **Load safe demo activity** or upload your own authorized logs.")
    else:
        left, right = st.columns(2)
        with left:
            counts = events.groupby("severity").size().reset_index(name="events")
            st.altair_chart(alt.Chart(counts).mark_bar(cornerRadiusTopRight=5).encode(x=alt.X("severity:N", sort=["Low", "Medium", "High", "Critical"]), y="events:Q", color="severity:N", tooltip=["severity", "events"]).properties(title="Event severity"), use_container_width=True)
        with right:
            timeline = events.copy(); timeline["hour"] = pd.to_datetime(timeline.timestamp).dt.floor("h")
            timeline = timeline.groupby("hour").size().reset_index(name="events")
            st.altair_chart(alt.Chart(timeline).mark_area(line=True).encode(x="hour:T", y="events:Q", tooltip=["hour", "events"]).properties(title="Activity timeline"), use_container_width=True)
        st.subheader("Latest analyst signals")
        st.dataframe(alerts[["severity", "title", "tactic", "technique", "status"]].head(10), use_container_width=True, hide_index=True) if not alerts.empty else st.caption("Run detections to create analyst signals.")

elif page == "Ingest logs":
    st.markdown("<div class='eyebrow'>Telemetry pipeline</div>", unsafe_allow_html=True)
    st.title("Ingest logs")
    st.write("Upload authorized CSV, JSON/JSONL, or text/syslog data. Everything stays on this machine.")
    uploaded = st.file_uploader("Choose a log export", type=["csv", "json", "jsonl", "ndjson", "log", "txt"])
    if uploaded:
        prepared = parse_upload(uploaded)
        st.dataframe(prepared.drop(columns=["raw"]).head(20), use_container_width=True, hide_index=True)
        if st.button("Normalize and ingest", type="primary"):
            st.success(f"Ingested {ingest(prepared)} events.")
    st.divider()
    if st.button("Run detection rules", type="primary"):
        st.success(f"Created {run_detections()} new alerts.")

elif page == "Alert queue":
    st.markdown("<div class='eyebrow'>Detection workspace</div>", unsafe_allow_html=True)
    st.title("Alert queue")
    if alerts.empty:
        st.info("No alerts yet. Ingest logs and run the detection rules.")
    else:
        selected = st.multiselect("Severity", sorted(alerts.severity.unique()), default=sorted(alerts.severity.unique()))
        display = alerts[alerts.severity.isin(selected)]
        st.dataframe(display[["id", "severity", "title", "tactic", "technique", "status", "evidence"]], use_container_width=True, hide_index=True)
        alert_id = st.selectbox("Update an alert", display.id.tolist(), format_func=lambda value: f"Alert #{value}")
        status = st.selectbox("Status", ["New", "Investigating", "Resolved"])
        if st.button("Save alert status"):
            with connection() as con: con.execute("UPDATE alerts SET status=? WHERE id=?", (status, int(alert_id)))
            st.rerun()

elif page == "Incidents":
    st.markdown("<div class='eyebrow'>Case management</div>", unsafe_allow_html=True)
    st.title("Incidents")
    with st.form("incident"):
        title = st.text_input("Incident title")
        severity = st.selectbox("Severity", ["Low", "Medium", "High", "Critical"])
        owner = st.text_input("Owner")
        notes = st.text_area("Investigation notes")
        if st.form_submit_button("Create incident") and title:
            with connection() as con: con.execute("INSERT INTO incidents (title,severity,status,owner,notes) VALUES (?,?,?,?,?)", (title, severity, "Open", owner, notes))
            st.rerun()
    incidents = query("SELECT * FROM incidents ORDER BY created_at DESC")
    if not incidents.empty: st.dataframe(incidents, use_container_width=True, hide_index=True)

elif page == "MITRE coverage":
    st.markdown("<div class='eyebrow'>Detection engineering</div>", unsafe_allow_html=True)
    st.title("MITRE ATT&CK coverage")
    if alerts.empty:
        st.info("Coverage appears after detection rules create alerts.")
    else:
        coverage = alerts.groupby(["tactic", "technique"]).size().reset_index(name="alerts")
        st.altair_chart(alt.Chart(coverage).mark_bar().encode(x="alerts:Q", y=alt.Y("technique:N", sort="-x"), color="tactic:N", tooltip=["tactic", "technique", "alerts"]), use_container_width=True)
        st.dataframe(coverage, use_container_width=True, hide_index=True)

else:
    st.markdown("<div class='eyebrow'>Analyst handoff</div>", unsafe_allow_html=True)
    st.title("Reports")
    st.write("Export the current analyst queue as CSV for a handoff or evidence package.")
    if alerts.empty:
        st.info("No alerts to export.")
    else:
        st.download_button("Download alert report", alerts.to_csv(index=False).encode(), "sentineldeck-alert-report.csv", "text/csv", type="primary")
