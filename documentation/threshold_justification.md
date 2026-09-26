# Password Spray Detection — Threshold Justification

## Detection Thresholds

| Parameter | Value |
|---|---|
| Unique users | 10 |
| Failed attempts | 15 |
| Time window | 10 minutes |

## Why These Thresholds?

The detection is designed to identify authentication failures
against multiple unique accounts from the same source IP.

A threshold of 10 unique accounts within 10 minutes is used
as an initial demonstration threshold.

A minimum of 15 failed attempts is also required.

These values are not universal industry standards.
They are initial tuning values for this project.

## Threshold Trade-offs

### Lower Threshold

Advantages:
- May detect smaller attacks earlier.
- May improve sensitivity.

Disadvantages:
- May increase false positives.
- Could alert on legitimate authentication issues.

### Higher Threshold

Advantages:
- May reduce alert volume.
- Requires a stronger concentration of activity.

Disadvantages:
- May miss smaller or slower password-spray attempts.
- Could delay detection.

## Tuning Considerations

In a real SOC, thresholds should be adjusted based on:

- Normal authentication baseline.
- Number of users in the environment.
- Known authentication gateways.
- VPN and proxy behavior.
- Service accounts.
- Known security-testing activity.
- Historical false-positive rate.

## Validation Results

| Dataset | Unique Users | Failed Attempts | Result |
|---|---:|---:|---|
| Password Spray | 15 | 15 | Detection |
| Normal Authentication | 1–3 per source | Low | No Detection |
| Edge Case | 9 | 9 | No Detection |

## Limitations

This project uses synthetic authentication logs.

The validation does not prove that the rule has been deployed
or tested in a production SIEM.

Real-world performance requires testing against representative
authentication data and tuning the thresholds accordingly.

## Local Validation Results

The detection logic was tested locally using three synthetic authentication datasets.

### Password Spray Dataset

- Total events: 15
- Source IP: 185.100.50.25
- Failed attempts: 15
- Unique users targeted: 15
- Result: Detection Triggered

### Normal Authentication Dataset

- Total events: 7
- Result: No Detection

### Edge Case Dataset

- Total events: 9
- Unique users targeted: 9
- Result: No Detection

The validation confirms that the detection logic identifies the
simulated password-spraying pattern while not triggering on the
normal and below-threshold test cases.

This is a local validation using synthetic data and does not
represent production SIEM deployment or production performance.