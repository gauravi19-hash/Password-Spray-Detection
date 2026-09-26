# Password Spray Detection

A SOC detection engineering project focused on identifying potential
password-spraying attacks using authentication logs, Splunk SPL, KQL,
and Python-based local validation.

## Project Overview

Password spraying is an authentication attack where an attacker attempts
a small number of commonly used or compromised passwords against many
different user accounts.

This project demonstrates how a SOC analyst can detect this behavior by
correlating failed authentication attempts from a single source IP
against multiple unique user accounts within a defined time window.

### Detection Hypothesis

> A single source IP generating failed authentication attempts against
> 10 or more unique user accounts within 10 minutes may indicate
> password-spraying activity.

The project uses synthetic authentication data to validate the detection
logic.

---

## Attack Technique

**MITRE ATT&CK:** T1110.003 — Password Spraying

Password spraying differs from traditional brute force:

| Attack | Typical Behavior |
|---|---|
| Password Spraying | One/few passwords against many accounts |
| Brute Force | Many password attempts against one account |

---

## Detection Logic

The detection evaluates:

- Failed authentication events
- Source IP address
- Number of unique targeted usernames
- Number of failed authentication attempts
- 10-minute time window

### Initial Detection Thresholds

| Parameter | Threshold |
|---|---:|
| Unique users | >= 10 |
| Failed attempts | >= 15 |
| Time window | 10 minutes |

These are initial demonstration/tuning values and are **not universal
industry standards**.

In a production SOC, thresholds should be tuned using the organization's
authentication baseline, false-positive history, VPN/proxy architecture,
service accounts, scanners, and other environmental factors.

---

## Project Structure

```text
Password-Spray-Detection/
│
├── documentation/
│   ├── detection_logic.md
│   ├── investigation_playbook.md
│   ├── threshold_justification.md
│   └── validate_detection.py
│
├── kql/
│   └── password_spray_detection.kql
│
├── sample_logs/
│   ├── password_spray.csv
│   ├── normal_authentication.csv
│   └── edge_case.csv
│
├── screenshots/
│   ├── validation_results.png
│   └── splunk_password_spray_detection.png
│
├── spl/
│   └── password_spray_detection.spl
│
├── .gitignore
└── README.md
Technologies & Skills Demonstrated
Security Operations Center (SOC) fundamentals
Detection engineering
Password-spray detection
Authentication log analysis
Splunk
Splunk Processing Language (SPL)
Kusto Query Language (KQL)
Python
Log correlation
Threshold tuning
Alert triage
Investigation playbook development
MITRE ATT&CK mapping
Detection validation
Git & GitHub
Splunk Detection

The Splunk detection groups failed authentication events by source IP
within a 10-minute window and counts distinct targeted usernames.

index=auth Action=Failure
| bin _time span=10m
| stats
    count as FailedAttempts
    dc(Username) as UniqueUsers
    values(Username) as TargetedUsers
    earliest(_time) as FirstSeen
    latest(_time) as LastSeen
    by SourceIP _time
| where UniqueUsers >= 10
    AND FailedAttempts >= 15
| eval FirstSeen=strftime(FirstSeen,"%Y-%m-%d %H:%M:%S")
| eval LastSeen=strftime(LastSeen,"%Y-%m-%d %H:%M:%S")
| eval Severity="High"
| eval MITRE_Technique="T1110.003 - Password Spraying"
| table SourceIP FailedAttempts UniqueUsers TargetedUsers FirstSeen LastSeen Severity MITRE_Technique
| sort - UniqueUsers

The SPL assumes the normalized fields:

SourceIP
Username
Action

and an auth Splunk index.

KQL Detection

A KQL version is also included for environments using Microsoft
Sentinel / Microsoft Entra authentication telemetry.

SigninLogs
| where ResultType != 0
| summarize
    FailedAttempts = count(),
    UniqueUsers = dcount(UserPrincipalName),
    TargetedUsers = make_set(UserPrincipalName, 20),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
    by IPAddress, bin(TimeGenerated, 10m)
| where UniqueUsers >= 10
    and FailedAttempts >= 15
| project
    TimeGenerated,
    IPAddress,
    FailedAttempts,
    UniqueUsers,
    TargetedUsers,
    FirstSeen,
    LastSeen
| order by UniqueUsers desc

The KQL uses the Microsoft SigninLogs schema and is provided as a
detection example rather than a claim of production deployment.

Python Validation

A Python validation script was created to test the detection logic
against synthetic authentication datasets without requiring a live
SIEM environment.

The validator:

Loads authentication CSV files.
Filters failed authentication events.
Groups events by source IP.
Sorts events chronologically.
Evaluates a 10-minute window.
Counts unique targeted users.
Counts failed authentication attempts.
Determines whether the configured thresholds are exceeded.
Validation Results

Three synthetic datasets were used.

Dataset	Unique Users	Failed Attempts	Expected Result
Password Spray	15	15	Detection
Normal Authentication	1–3 per source	Low	No Detection
Edge Case	9	9	No Detection
Password Spray Dataset
Source IP: 185.100.50.25
Failed attempts: 15
Unique users: 15
Result: DETECTION TRIGGERED
Normal Authentication Dataset
Result: NO DETECTION
Edge Case Dataset
Unique users: 9
Result: NO DETECTION

The results confirm that the detection identifies the simulated
password-spraying pattern while remaining below the configured
threshold for the edge-case dataset.

Splunk Validation

The detection was also tested locally in Splunk using the synthetic
authentication datasets.

The final detection returned the simulated password-spray source:

Source IP:       185.100.50.25
Failed attempts: 15
Unique users:    15
Severity:        High
MITRE:           T1110.003 - Password Spraying
Splunk Detection Screenshot

Python Validation Screenshot

SOC Investigation Workflow

When this detection triggers, an analyst should investigate:

1. Validate the Alert

Confirm:

Authentication attempts are failures.
Multiple unique accounts were targeted.
The events originated from the same source IP.
The configured threshold was exceeded.
The activity occurred within the expected time window.
2. Investigate the Source IP

Determine whether the IP belongs to:

Internal infrastructure
VPN infrastructure
Corporate proxy
Security scanner
Known trusted service
Unknown external source

Threat-intelligence sources may be consulted where appropriate.

3. Investigate Targeted Accounts

Review:

Number of targeted accounts
Privileged accounts
Service accounts
Disabled or inactive accounts
Recently created accounts
4. Search for Successful Authentication

Look for successful authentication from the same source IP during
or after the failed attempts.

A successful login following password-spray activity requires
additional investigation.

5. Correlate Related Activity

Search for:

MFA events
VPN activity
Endpoint alerts
Additional authentication failures
Suspicious network activity
Other alerts involving the same IP or accounts
Example Response Actions

If malicious activity is confirmed, response may include:

Escalating according to the organization's incident-response process.
Restricting the source where authorized.
Investigating potentially affected accounts.
Resetting credentials when required.
Reviewing MFA configuration and authentication activity.
Searching for successful authentication from the source.
Preserving relevant investigation evidence.

Actual containment actions should follow organizational procedures
and authorization requirements.

Threshold Tuning

The project intentionally documents the trade-off between sensitivity
and false positives.

Lower Threshold

May detect smaller attacks earlier, but can increase false positives.

Higher Threshold

May reduce alert volume, but can miss smaller or slower attacks.

Production tuning should consider:

Authentication baseline
User population
VPN and proxy behavior
Service accounts
Security scanners
Historical false positives
Authentication architecture
Attack patterns observed in the environment

See:

documentation/threshold_justification.md

for the detailed threshold discussion.

Limitations

This project uses synthetic authentication logs.

The validation demonstrates that the detection logic works against the
provided test cases, but it does not establish production detection
performance.

The project does not represent:

Production SIEM deployment
Production alert volume
Production false-positive rate
Real-world attack prevalence
Enterprise-scale performance

Additional testing with representative authentication telemetry would
be required before production deployment.

Files
Detection
spl/password_spray_detection.spl — Splunk detection
kql/password_spray_detection.kql — KQL detection example
Validation
documentation/validate_detection.py — Python validation script
Documentation
documentation/detection_logic.md — Detection methodology
documentation/investigation_playbook.md — SOC investigation workflow
documentation/threshold_justification.md — Threshold rationale
Sample Data
sample_logs/password_spray.csv
sample_logs/normal_authentication.csv
sample_logs/edge_case.csv
Project Outcome

This project demonstrates an end-to-end detection engineering workflow:

Attack Scenario
      ↓
Detection Hypothesis
      ↓
Synthetic Authentication Logs
      ↓
Detection Logic
      ↓
Splunk / KQL Implementation
      ↓
Python Validation
      ↓
Detection Results
      ↓
SOC Investigation Playbook
      ↓
MITRE ATT&CK Mapping

The project focuses on demonstrating practical SOC analyst skills in
authentication monitoring, detection logic, validation, and alert
investigation.
