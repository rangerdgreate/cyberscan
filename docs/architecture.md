# CyberScan Architecture

CyberScan is a local-first vulnerability scanning system. It runs as a Python web app, serves the browser UI, executes safe scanner checks, and stores reports on disk.

## System Flow

```text
User
  -> Browser UI (prototype.html)
  -> Python Web App (app.py)
  -> CyberScan Engine (cyberscan.py)
  -> File-Based Storage (reports/)
```

## Main Components

- `prototype.html`: desktop-style web interface for login, scans, findings, reports, settings, and FAQ.
- `app.py`: local HTTP API, session handling, scan jobs, report automation, history, and triage persistence.
- `cyberscan.py`: scanner engine, crawler, OWASP-aligned checks, finding metadata, and report exporters.
- `reports/history.json`: saved scan history.
- `reports/automation.json`: report automation schedules.
- `reports/triage.json`: persisted finding triage states.
- `reports/*.json`, `*.csv`, `*.html`: generated scan reports.

## Scan Job Flow

```text
Start Scan
  -> POST /api/scan with background=true
  -> API creates queued job
  -> background worker runs CyberScan
  -> UI polls /api/scan/jobs/{scan_id}
  -> completed report is applied to dashboard, results, and reports
```

## Persistence Model

CyberScan intentionally uses file-based persistence instead of a database. This keeps the system portable, easy to run locally, and simple to inspect during authorized testing and capstone demonstrations.

The system persists:

- scan history
- generated reports
- weekly report schedules
- finding triage actions such as false positive, accepted risk, owner review, and hidden/deleted findings

## Security Boundaries

- The scanner requires users to confirm authorization before launching scans.
- Login uses a configurable local owner password.
- Cross-origin POST requests are rejected.
- Generated reports are served from the local `reports` directory only.
- Scanner checks are safe indicators and do not attempt destructive exploitation.
