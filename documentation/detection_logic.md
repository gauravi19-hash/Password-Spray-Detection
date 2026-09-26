# Password Spray Detection Logic

## Objective

Detect potential password-spraying activity by identifying authentication
failures from a single source IP against multiple unique user accounts
within a short time window.

## Detection Hypothesis

A source generating failed authentication attempts against 10 or more
unique accounts within 10 minutes may indicate password-spraying activity.

## Detection Conditions

- Authentication attempt must be unsuccessful.
- Events are grouped by source IP.
- Events are evaluated within a 10-minute time window.
- At least 10 unique user accounts must be targeted.

## Expected Behavior

| Dataset | Unique Users | Expected Result |
|---|---:|---|
| Password Spray | 15 | Detection |
| Normal Authentication | 1–3 per source | No Detection |
| Edge Case | 9 | No Detection |

## Detection Signal

The primary detection signal is the number of distinct user accounts
targeted by the same source IP within the defined time window.

This is intended to identify password spraying rather than traditional
single-account brute-force activity.