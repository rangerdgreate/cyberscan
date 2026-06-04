# CyberScan User Manual

## Start the System

Install dependencies:

```powershell
pip install -r requirements.txt
```

Run the local web app:

```powershell
python app.py
```

Open:

```text
http://127.0.0.1:8006/
```

## Sign In

Use the local owner password configured for the app. For prototype use, the default password is:

```text
password
```

To set a custom password before starting the app:

```powershell
$env:CYBERSCAN_OWNER_PASSWORD = "a-long-local-password"
python app.py
```

## Run a Scan

1. Open **Scan Setup**.
2. Enter one or more target URLs.
3. Select a scan type:
   - **Quick**: shallow baseline scan.
   - **Full**: broader crawl and checks.
   - **Authenticated**: session-aware scan with authorized headers or cookies.
4. Confirm that you own the target or have explicit permission.
5. Click **Start Scan**.

The UI shows the real background scan job status while the Python scanner runs.

## Review Results

Open **Results** after a scan completes. Findings include:

- severity
- OWASP category
- affected URL
- evidence
- CWE mapping
- confidence
- lifecycle status

You can mark findings as:

- False Positive
- Accepted Risk
- Owner Review

These triage actions are saved in `reports/triage.json`.

## Generate Reports

Open **Reports** and generate one of the available report templates:

- Executive Summary
- Developer Handoff
- Full Technical Report
- Compliance Report

Reports are saved in the `reports` folder.

## Interpret Finding Metadata

- **Severity**: estimated impact level.
- **CWE**: weakness category mapping.
- **Confidence**: how strongly the scanner observed the issue.
- **Validation Status**: whether the finding is observed, informational, or needs manual validation.
- **Lifecycle Status**: whether the finding is new, existing, fixed, false positive, or accepted risk.

## Responsible Use

CyberScan is for authorized security testing only. Do not scan systems you do not own or do not have explicit permission to assess.
