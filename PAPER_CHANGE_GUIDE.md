# CyberScan Paper Change Guide

Use this guide to update Chapters 1, 2, and 3 after the latest CyberScan system improvements.

## Chapter 1: The Problem and Its Background

### 1. Background of the Study

Where to put the change:

Place this near the part where the paper introduces CyberScan and explains why the system is needed.

Suggested update:

```text
CyberScan is designed as a local web-based vulnerability scanning system that assists authorized users in identifying common web security weaknesses. The system includes a Python-based scanning engine, a browser-based user interface, background scan job tracking, finding triage, report generation, and file-based persistence for scan history and automation data.
```

### 2. Statement of the Problem

Where to put the change:

Add these after the existing problems about manual vulnerability checking or lack of automated scanning.

Suggested additional problems:

```text
1. Manual vulnerability assessment can make it difficult to consistently track scan results and compare findings over time.
2. Users may lack a simple way to classify findings as new, existing, false positive, accepted risk, or needing owner review.
3. Small teams may need a local reporting tool that does not require a separate database server or cloud service.
4. Users may need visible scan job status while a scan is running, especially for longer scans.
```

### 3. Objectives of the Study

Where to put the change:

Update the general and specific objectives section.

Suggested specific objectives:

```text
The study aims to develop a local web-based vulnerability scanning system with the following objectives:

1. To design and implement a Python-based web vulnerability scanner for authorized testing.
2. To provide scan profiles such as Quick, Full, and Authenticated scans.
3. To map findings to OWASP Top 10 categories and CWE identifiers.
4. To generate JSON, CSV, and HTML reports.
5. To implement scan history and comparison of new, existing, and fixed findings.
6. To provide background scan job tracking with queued, running, complete, failed, and cancelled states.
7. To allow users to triage findings as False Positive, Accepted Risk, or Owner Review.
8. To use file-based persistence for local scan history, automation settings, reports, and triage data.
```

### 4. Scope and Limitations

Where to put the change:

Replace or revise any statement saying the system is only a static prototype.

Suggested update:

```text
The system is a local full working web-based vulnerability scanner intended for authorized testing environments. It uses file-based persistence instead of a database. Scan history is stored in JSON format, generated reports are exported as JSON, CSV, and HTML files, and finding triage states are saved locally.

The system does not perform destructive exploitation, brute-force attacks, credential cracking, database extraction, authentication bypass, or SSRF testing. Findings should be treated as prioritized indicators that require human validation before remediation sign-off.
```

### 5. Significance of the Study

Where to put the change:

Add this to the part explaining who benefits from the study.

Suggested update:

```text
The system benefits students, developers, system owners, and security testers by providing a local tool for safe vulnerability scanning, report generation, and finding management. It also supports learning by showing OWASP categories, CWE mappings, confidence levels, validation status, and remediation recommendations.
```

## Chapter 2: Review of Related Literature and Studies

### 1. Automated Vulnerability Scanning

Where to put the change:

Add or expand the section discussing vulnerability scanners.

Mention:

```text
Automated scanners help identify common web application weaknesses such as missing security headers, insecure cookies, exposed files, unsafe forms, outdated components, and injection indicators. CyberScan follows this concept by implementing safe OWASP-aligned checks for authorized environments.
```

### 2. OWASP Top 10

Where to put the change:

Add this where the paper discusses web application security risks.

Mention:

```text
The OWASP Top 10 provides a widely recognized classification of common web application security risks. CyberScan uses OWASP categories to organize findings and make reports easier to understand.
```

### 3. CWE Mapping

Where to put the change:

Add this after the OWASP Top 10 discussion or in a vulnerability classification section.

Mention:

```text
CWE identifiers provide standardized weakness references. CyberScan includes CWE mapping in each finding to support clearer technical documentation and remediation planning.
```

### 4. Vulnerability Reporting

Where to put the change:

Add this in the section about reporting, documentation, or security assessment output.

Mention:

```text
Security reports help communicate risk, evidence, and remediation steps. CyberScan generates reports in JSON, CSV, and HTML formats to support both machine-readable and human-readable outputs.
```

### 5. Finding Triage

Where to put the change:

Add this as a new related concept if it does not exist yet.

Mention:

```text
Finding triage is the process of reviewing scanner results and classifying them according to their validity and treatment. CyberScan supports triage states such as False Positive, Accepted Risk, and Owner Review.
```

### 6. File-Based Persistence

Where to put the change:

Add this if the paper currently assumes database storage or does not explain storage.

Mention:

```text
File-based persistence stores application data in local files instead of a database server. This approach is suitable for local-first tools because it simplifies deployment and allows users to inspect generated outputs directly.
```

### 7. Background Job Processing

Where to put the change:

Add this in the system design concepts or related technology section.

Mention:

```text
Background job processing allows long-running operations to continue without blocking the user interface. CyberScan applies this by creating scan jobs with statuses such as queued, running, complete, failed, and cancelled.
```

## Chapter 3: Methodology and System Design

Chapter 3 needs the most updates.

### 1. System Architecture

Where to put the change:

Replace the old architecture description or add this under the architecture section.

Suggested architecture:

```text
Browser User Interface
        ↓
Python Web Application
        ↓
CyberScan Scanner Engine
        ↓
File-Based Storage
```

Suggested explanation:

```text
The system follows a local-first architecture. The browser-based interface communicates with the Python web application, which manages login, scan jobs, report generation, scan history, report scheduling, and finding triage. The CyberScan engine performs safe vulnerability checks and produces structured findings. Outputs are stored using file-based persistence.
```

### 2. System Modules

Where to put the change:

Add this to the module description section.

Suggested modules:

```text
1. Login Module - handles local owner access to the system.
2. Scan Configuration Module - allows users to enter targets and configure scan profiles.
3. Background Scan Job Module - tracks scan status as queued, running, complete, failed, or cancelled.
4. Vulnerability Detection Module - performs safe OWASP-aligned web security checks.
5. Report Generation Module - exports reports in JSON, CSV, and HTML formats.
6. Scan History Module - stores previous scan results for review and comparison.
7. Finding Triage Module - saves user decisions such as False Positive, Accepted Risk, and Owner Review.
8. Report Scheduling Module - supports scheduled generation of report templates.
```

### 3. Data Storage / Persistence

Where to put the change:

Add this where the paper discusses database, files, or storage.

Suggested update:

```text
The system uses file-based persistence rather than a database. The main storage files are:

- reports/history.json for scan history
- reports/automation.json for report schedules and generated report metadata
- reports/triage.json for finding triage states
- generated JSON, CSV, and HTML files for scan reports

This approach supports portability and simplifies local deployment.
```

### 4. Data Flow

Where to put the change:

Update the Data Flow Diagram explanation.

Suggested flow:

```text
1. The user logs in to the local CyberScan interface.
2. The user configures a target and confirms authorization.
3. The system creates a background scan job.
4. The scanner engine crawls and analyzes the target.
5. The system generates structured findings with OWASP, CWE, confidence, and validation metadata.
6. The system exports JSON, CSV, and HTML reports.
7. The user views findings and applies triage decisions.
8. The system saves scan history, reports, schedules, and triage states using local files.
```

### 5. Use Case Diagram

Where to put the change:

Add these use cases to the actor/use case section.

Suggested use cases:

```text
- Login
- Configure Scan
- Start Scan
- Cancel Scan
- View Scan Status
- View Findings
- Mark Finding as False Positive
- Accept Risk
- Mark for Owner Review
- Generate Report
- Schedule Report
- View Scan History
```

### 6. Testing

Where to put the change:

Add this under testing, evaluation, or system validation.

Suggested update:

```text
The system was validated using automated regression tests for core scanner behavior, report comparison, crawl scope handling, login validation, report generation, background scan jobs, and finding triage. The current test suite contains 12 passing tests.
```

Test result:

```text
Ran 12 tests
OK
```

## Summary of Required Paper Changes

```text
Chapter 1: update scope, objectives, problem statement, limitations, and significance.
Chapter 2: add related concepts for OWASP, CWE, reporting, triage, file-based persistence, and background jobs.
Chapter 3: update architecture, modules, storage, data flow, use cases, and testing.
```

