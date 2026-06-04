# CyberScan: An Automated Web Vulnerability Scanner Built with Python

CyberScan is a local web vulnerability scanner for authorized testing environments. It includes a Python scan engine, a desktop-style web UI, and JSON, CSV, and HTML report exports.
It also compares each new scan with the previous saved scan so teams can see new, existing, and fixed findings over time.

## Install requirements

```powershell
pip install -r requirements.txt
```

## How to run

```powershell
python cyberscan.py https://example.com --confirm-authorized
```

Or save with a custom report name:

```powershell
python cyberscan.py https://example.com --confirm-authorized --json report.json --csv report.csv --html report.html
```

For session-aware scans, pass authorized request headers or cookies:

```powershell
python cyberscan.py https://example.com --confirm-authorized --scan-type Authenticated --header "Authorization: Bearer TOKEN" --cookie "sessionid=VALUE"
```

Scan profiles provide safe defaults:

- `Quick`: shallow baseline checks for target URLs, TLS, headers, cookies, and known exposure paths.
- `Full`: balanced crawling, form review, safe SQL/XSS indicators, sensitive path checks, and report comparison.
- `Authenticated`: session-aware scanning using authorized headers or cookies, broader page limits, and access-control indicators.

To launch the local web app:

```powershell
python app.py
```

The web app serves the prototype UI and saves generated reports in the `reports` folder. Before a web scan starts, the UI requires confirmation that the user owns the target or has explicit permission to scan it.
Report template generation and weekly report schedules are automated by the local web app while `app.py` is running. Use the Reports page to generate a template immediately or enable a weekly schedule; schedule state is saved in `reports/automation.json`.
Scan comparison state is saved with each history entry in `reports/history.json` and exported in JSON, CSV, and HTML reports.

By default the local owner password is `password` for prototype use. Set one of these environment variables before launching the web app for a less guessable local login:

```powershell
$env:CYBERSCAN_OWNER_PASSWORD = "a-long-local-password"
python app.py
```

Or provide a SHA-256 hash:

```powershell
$env:CYBERSCAN_OWNER_PASSWORD_HASH = "<sha256-hex-digest>"
python app.py
```

The web API rejects cross-origin POST requests by default and only reflects local `localhost` or `127.0.0.1` origins.

For long-running integrations, `/api/scan` also supports background jobs by passing `"background": true`. The response returns `202 Accepted` with a `scan_id`; poll `/api/scan/jobs/{scan_id}` for `queued`, `running`, `complete`, `failed`, or `cancelled`.

## Verification

Run the core regression checks with:

```powershell
python -m unittest discover -s tests
```

Optional project tooling is declared in `pyproject.toml`. Install dev tooling and run Ruff with:

```powershell
pip install -e ".[dev]"
ruff check .
```

## Documentation

- `USER_MANUAL.md`: operator guide for sign-in, scans, triage, reports, and responsible use.
- `docs/architecture.md`: local-first system architecture, scan job flow, and file-based persistence model.

## What this scanner can check

- A01 Broken Access Control: possible public access to `/admin`, `/dashboard`, and `/settings`
- A01 Broken Access Control: sensitive API exposure indicators for common user, basket, admin, and account routes
- A02 Cryptographic Failures: no HTTPS and SSL certificate issues
- A03 Injection: missing Content Security Policy and form/input risk indicators
- A03 Injection: weak Content Security Policy patterns such as unsafe inline script or broad sources
- A03 Injection: safe SQL error indicators using limited quote probes on in-scope GET parameters
- A03 Injection: reflected XSS indicators using harmless marker reflection checks
- A03 Injection: DOM XSS source-to-sink patterns in inline JavaScript
- A03 Injection: stored XSS review candidates for user-content forms
- A03 Injection: safe checks for common search API SQL/XSS indicators on authorized lab targets
- A04 Insecure Design: suspicious external form submission
- A05 Security Misconfiguration: missing security headers, directory listing, exposed sensitive files, and error message disclosure
- A06 Vulnerable and Outdated Components: visible library versions such as jQuery, Bootstrap, and Angular
- A07 Identification and Authentication Failures: insecure cookies, password form issues, and client-side authentication surface indicators
- A09 Security Logging and Monitoring Failures: limited only; cannot fully verify internal logging
- A10 Server-Side Request Forgery: not included in this safe prototype

## Reporting improvements

Every finding now includes:

- Severity
- OWASP category
- CWE mapping when applicable
- Confidence level: `High`, `Medium`, or `Low`
- Validation status such as `Observed`, `Needs Manual Validation`, or `Informational`
- Lifecycle status from comparison: `New`, `Existing`, or fixed in the comparison summary

The web UI also supports triage states such as `False Positive`, `Accepted Risk`, and `Owner Review`.
Reports include discovery context from sources such as `robots.txt`, `sitemap.xml`, form actions, and inline route hints when available.

## Current boundaries

CyberScan now supports controlled crawling, request headers, session cookies, evidence capture, safe OWASP-aligned probes, CWE/confidence metadata, discovery context, scan profiles, and report export, but it remains a safe scanner. It does not brute force credentials, extract database data, execute stored payloads, bypass authentication, verify server-side logging, or test SSRF. Treat findings as prioritized indicators that need human validation before remediation sign-off.
