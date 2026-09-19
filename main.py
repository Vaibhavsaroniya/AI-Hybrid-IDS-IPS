"""
Hybrid IDS Dashboard — Backend
--------------------------------
Read-only FastAPI service. Reads logs/live_security_events.csv (written by
live_flow_builder.py, unchanged) and serves it as JSON for the frontend.

This process never writes to, modifies, or deletes the log file, and has
no ability to send anything back into the detection pipeline.

Run:
    pip install fastapi uvicorn pandas
    uvicorn main:app --reload --port 8080

Then open http://localhost:8080 in the browser.
"""

import os
import time
from datetime import datetime
from typing import Optional

import pandas as pd
from fastapi import FastAPI, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

# ============================================================
# CONFIG
# ============================================================

# Defaults to ../logs/live_security_events.csv relative to this file,
# i.e. this "dashboard" folder is expected to live inside
# AI-Hybrid-IDS-IPS/ alongside the existing "logs" folder.
# Override with the IDS_LOG_PATH environment variable if needed.
LOG_PATH = os.environ.get(
    "IDS_LOG_PATH",
    os.path.join(os.path.dirname(__file__), "..", "logs", "live_security_events.csv"),
)

COLUMNS = [
    "Time", "Source", "Destination", "Protocol", "Source Port",
    "Destination Port", "AI Prediction", "AI Confidence", "AI Status",
    "Rule Alerts", "Rule Score", "Risk Score", "Severity", "Final Decision",
]

CAPTURING_FRESHNESS_SECONDS = 15  # log written to within this window = "live"

app = FastAPI(title="Hybrid IDS Dashboard API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["GET"],
    allow_headers=["*"],
)


# ============================================================
# DATA LOADING (read-only, tolerant of a file being actively written)
# ============================================================

def load_events() -> pd.DataFrame:
    """
    Reads the log CSV defensively:
      - returns an empty, correctly-columned DataFrame if the file doesn't
        exist yet or has no data
      - skips any malformed trailing line (can happen if we read mid-write)
        instead of crashing
    """
    if not os.path.exists(LOG_PATH):
        return pd.DataFrame(columns=COLUMNS)

    try:
        df = pd.read_csv(LOG_PATH, on_bad_lines="skip", engine="python")
    except pd.errors.EmptyDataError:
        return pd.DataFrame(columns=COLUMNS)
    except Exception:
        # Last line may have been mid-write; retry once, dropping it if needed
        try:
            with open(LOG_PATH, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()
            if len(lines) > 1:
                from io import StringIO
                df = pd.read_csv(StringIO("".join(lines[:-1])), on_bad_lines="skip")
            else:
                return pd.DataFrame(columns=COLUMNS)
        except Exception:
            return pd.DataFrame(columns=COLUMNS)

    for col in COLUMNS:
        if col not in df.columns:
            df[col] = None

    df["Time"] = pd.to_datetime(df["Time"], errors="coerce")
    df = df.dropna(subset=["Time"])
    df = df.sort_values("Time")
    return df


def is_capturing() -> bool:
    if not os.path.exists(LOG_PATH):
        return False
    age = time.time() - os.path.getmtime(LOG_PATH)
    return age <= CAPTURING_FRESHNESS_SECONDS


# ============================================================
# API — SUMMARY
# ============================================================

@app.get("/api/summary")
def summary():
    df = load_events()
    total = len(df)

    if total == 0:
        return {
            "total": 0, "normal": 0, "suspicious": 0, "threat": 0,
            "capturing": is_capturing(), "last_event_time": None,
        }

    decision = df["Final Decision"].astype(str)
    normal = int((decision == "NORMAL").sum())
    threat = int(decision.str.contains("THREAT", case=False, na=False).sum())
    suspicious = int(
        decision.str.contains("SUSPICIOUS", case=False, na=False).sum()
    )

    return {
        "total": total,
        "normal": normal,
        "suspicious": suspicious,
        "threat": threat,
        "capturing": is_capturing(),
        "last_event_time": df["Time"].max().isoformat(),
    }


# ============================================================
# API — LIVE ALERT FEED (non-normal, most recent first)
# ============================================================

@app.get("/api/alerts")
def alerts(limit: int = Query(50, ge=1, le=500)):
    df = load_events()
    if df.empty:
        return []

    non_normal = df[df["Final Decision"].astype(str) != "NORMAL"]
    non_normal = non_normal.sort_values("Time", ascending=False).head(limit)
    non_normal = non_normal.fillna("")  # NaN (e.g. empty MULTI-row fields) isn't valid JSON

    return [
        {
            "time": row["Time"].isoformat(),
            "source": row["Source"],
            "destination": row["Destination"],
            "protocol": row["Protocol"],
            "rule_alerts": row["Rule Alerts"],
            "ai_prediction": row["AI Prediction"],
            "severity": row["Severity"],
            "final_decision": row["Final Decision"],
            "risk_score": row["Risk Score"],
        }
        for _, row in non_normal.iterrows()
    ]


# ============================================================
# API — SEVERITY BREAKDOWN (for the donut/bar chart)
# ============================================================

@app.get("/api/charts/severity")
def severity_breakdown():
    df = load_events()
    if df.empty:
        return {"NONE": 0, "LOW": 0, "MEDIUM": 0, "HIGH": 0}

    counts = df["Severity"].astype(str).value_counts().to_dict()
    return {level: int(counts.get(level, 0)) for level in ["NONE", "LOW", "MEDIUM", "HIGH"]}


# ============================================================
# API — EVENT VOLUME OVER TIME (for the timeline chart)
# ============================================================

@app.get("/api/charts/timeline")
def timeline(minutes: int = Query(30, ge=1, le=720)):
    df = load_events()
    if df.empty:
        return {"labels": [], "normal": [], "suspicious": [], "threat": []}

    cutoff = pd.Timestamp.now() - pd.Timedelta(minutes=minutes)
    df = df[df["Time"] >= cutoff]
    if df.empty:
        return {"labels": [], "normal": [], "suspicious": [], "threat": []}

    df = df.set_index("Time")
    decision = df["Final Decision"].astype(str)

    is_threat = decision.str.contains("THREAT", case=False, na=False)
    is_suspicious = decision.str.contains("SUSPICIOUS", case=False, na=False) & ~is_threat
    is_normal = ~is_threat & ~is_suspicious

    bucket = "1min" if minutes <= 60 else "5min"

    normal_series = is_normal.resample(bucket).sum()
    suspicious_series = is_suspicious.resample(bucket).sum()
    threat_series = is_threat.resample(bucket).sum()

    labels = [t.strftime("%H:%M") for t in normal_series.index]

    return {
        "labels": labels,
        "normal": normal_series.astype(int).tolist(),
        "suspicious": suspicious_series.astype(int).tolist(),
        "threat": threat_series.astype(int).tolist(),
    }


# ============================================================
# API — TOP OFFENDING SOURCE IPs
# ============================================================

@app.get("/api/top-offenders")
def top_offenders(limit: int = Query(10, ge=1, le=50)):
    df = load_events()
    if df.empty:
        return []

    non_normal = df[df["Final Decision"].astype(str) != "NORMAL"]
    if non_normal.empty:
        return []

    counts = non_normal["Source"].value_counts().head(limit)
    return [{"source": ip, "count": int(c)} for ip, c in counts.items()]


# ============================================================
# API — FULL EVENT LOG (paginated + filterable)
# ============================================================

@app.get("/api/events")
def events(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=500),
    severity: Optional[str] = None,
    source: Optional[str] = None,
    start: Optional[str] = None,
    end: Optional[str] = None,
):
    df = load_events()
    if df.empty:
        return {"total": 0, "page": page, "page_size": page_size, "events": []}

    df = df.sort_values("Time", ascending=False)

    if severity and severity.upper() != "ALL":
        df = df[df["Severity"].astype(str).str.upper() == severity.upper()]
    if source:
        df = df[df["Source"].astype(str).str.contains(source, case=False, na=False)]
    if start:
        start_ts = pd.to_datetime(start, errors="coerce")
        if pd.notna(start_ts):
            df = df[df["Time"] >= start_ts]
    if end:
        end_ts = pd.to_datetime(end, errors="coerce")
        if pd.notna(end_ts):
            df = df[df["Time"] <= end_ts]

    total = len(df)
    start_idx = (page - 1) * page_size
    page_df = df.iloc[start_idx:start_idx + page_size]

    records = page_df.copy()
    records["Time"] = records["Time"].dt.strftime("%Y-%m-%d %H:%M:%S")
    records = records.fillna("")

    return {
        "total": total,
        "page": page,
        "page_size": page_size,
        "events": records.to_dict(orient="records"),
    }


# ============================================================
# SERVE FRONTEND (static files)
# ============================================================

app.mount("/", StaticFiles(directory=os.path.join(os.path.dirname(__file__), "static"), html=True), name="static")
