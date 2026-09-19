# Hybrid IDS Dashboard — Setup

Tested and working (backend endpoints + static file serving all verified,
including reading the log file while it's mid-write, without crashing).

## Where to put this

Place the whole `dashboard/` folder **inside** `~/AI-Hybrid-IDS-IPS/`, next
to the existing `logs/` folder, like this:

```
AI-Hybrid-IDS-IPS/
├── logs/
│   └── live_security_events.csv
├── live_flow_builder.py
├── ...
└── dashboard/              <-- this folder
    ├── main.py
    └── static/
        ├── index.html
        ├── history.html
        ├── style.css
        └── app.js
```

By default it reads `../logs/live_security_events.csv` relative to
`main.py` — i.e. it expects to sit one level inside `AI-Hybrid-IDS-IPS/`
exactly as shown above. If you put it somewhere else, set the
`IDS_LOG_PATH` environment variable to the correct path.

## Install and run

```bash
cd ~/AI-Hybrid-IDS-IPS
source venv/bin/activate
pip install fastapi uvicorn pandas

cd dashboard
uvicorn main:app --host 0.0.0.0 --port 8080
```

Then open **http://localhost:8080** in Firefox inside the Ubuntu VM.

Leave `live_flow_builder.py` running in its own terminal as usual — the
dashboard only reads the log file, it never touches detection.

## Pages

- **`/` (Overview)** — live status pill, metric cards, live alert feed,
  severity donut chart, event-volume timeline, top offending source IPs.
  Auto-refreshes every 3 seconds.
- **`/history.html` (Event Log)** — full historical, filterable
  (severity + source IP), paginated table.

## Notes

- Read-only by design — no endpoint writes to or modifies the CSV.
- The "CAPTURING / IDLE" status pill is based on whether the log file was
  modified in the last 15 seconds (a proxy for "the detector is actively
  running"), not a direct connection to `live_flow_builder.py`.
- If you ever change the CSV's column names/order in the detector, update
  the `COLUMNS` list at the top of `main.py` to match.
