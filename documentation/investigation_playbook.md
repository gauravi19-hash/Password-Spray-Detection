# Password Spray Detection — Investigation Playbook

## Alert Overview

A password-spray detection triggered when a single source IP
generated failed authentication attempts against multiple unique
user accounts within a 10-minute window.

## Detection Trigger

- Source IP: 185.100.50.25
- Failed attempts: 15
- Unique users: 15
- Time window: 10 minutes
- MITRE ATT&CK: T1110.003 — Password Spraying

## SOC Analyst Triage

### 1. Validate the Alert

Confirm that:

- Authentication attempts are failures.
- Multiple unique accounts were targeted.
- Activity originated from the same source IP.
- The activity occurred within the configured time window.
- The detection threshold was actually exceeded.

### 2. Investigate the Source IP

Determine whether the source IP is:

- Internal
- External
- A known VPN gateway
- A corporate proxy
- A security scanner
- A known trusted service
- Unknown or suspicious

Check available threat-intelligence sources where appropriate.

### 3. Investigate Targeted Accounts

Review:

- Number of targeted accounts
- Account names
- Privileged accounts
- Service accounts
- Recently created accounts
- Disabled or inactive accounts

### 4. Check for Successful Authentication

Search for successful authentication events from the same
source IP after or during the failed attempts.

A successful authentication following password-spray activity
should increase investigation priority.

### 5. Correlate Related Activity

Look for:

- Additional authentication failures
- Successful logins
- MFA events
- VPN activity
- Endpoint alerts
- Suspicious network activity
- Other alerts involving the same source IP or accounts

## Initial Severity

Suggested project classification:

**High**

This classification is based on the simulated scenario involving
multiple targeted accounts from a single source.

Severity should be adjusted in a real SOC based on organizational
context, asset criticality, account privilege, successful
authentication, and other correlated evidence.

## Recommended Response

If the activity is confirmed as malicious:

1. Escalate the incident according to SOC procedures.
2. Consider blocking or restricting the source IP where appropriate.
3. Investigate potentially compromised accounts.
4. Reset credentials for affected accounts when required.
5. Review MFA status and authentication logs.
6. Search for successful authentication from the same source.
7. Preserve relevant logs and investigation evidence.

## Important Note

The response actions above are investigation recommendations for
this project. Actual containment actions should follow the
organization's incident-response procedures and authorization
requirements.

## Investigation Outcome

For this synthetic dataset:

- Password-spray pattern detected.
- 15 unique accounts targeted.
- 15 failed authentication attempts observed.
- No successful authentication event is included in the attack dataset.
- No production system was involved.

This project demonstrates detection and local validation only.