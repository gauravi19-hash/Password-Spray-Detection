import csv
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path


# Detection configuration
UNIQUE_USER_THRESHOLD = 10
FAILED_ATTEMPT_THRESHOLD = 15
WINDOW_MINUTES = 10


def load_logs(file_path):
    """Read authentication events from a CSV file."""
    logs = []

    with open(file_path, "r", newline="", encoding="utf-8") as file:
        reader = csv.DictReader(file)

        for row in reader:
            timestamp = datetime.strptime(
                row["Timestamp"],
                "%Y-%m-%d %H:%M:%S"
            )

            logs.append({
                "timestamp": timestamp,
                "source_ip": row["SourceIP"],
                "username": row["Username"],
                "action": row["Action"],
            })

    return logs


def detect_password_spray(logs):
    """Detect multiple failed logins against unique users."""

    failed_logs = [
        log for log in logs
        if log["action"].lower() == "failure"
    ]

    alerts = []

    # Group failed events by source IP
    grouped_by_ip = defaultdict(list)

    for log in failed_logs:
        grouped_by_ip[log["source_ip"]].append(log)

    # Evaluate each source IP
    for source_ip, events in grouped_by_ip.items():

        events.sort(key=lambda event: event["timestamp"])

        for start_index, start_event in enumerate(events):

            window_start = start_event["timestamp"]
            window_end = window_start + timedelta(
                minutes=WINDOW_MINUTES
            )

            window_events = [
                event
                for event in events[start_index:]
                if event["timestamp"] < window_end
            ]

            unique_users = set(
                event["username"]
                for event in window_events
            )

            failed_attempts = len(window_events)

            if (
                len(unique_users) >= UNIQUE_USER_THRESHOLD
                and failed_attempts >= FAILED_ATTEMPT_THRESHOLD
            ):
                alerts.append({
                    "source_ip": source_ip,
                    "window_start": window_start,
                    "window_end": window_end,
                    "failed_attempts": failed_attempts,
                    "unique_users": len(unique_users),
                    "targeted_users": sorted(unique_users),
                })

                break

    return alerts


def main():

    project_root = Path(__file__).resolve().parent.parent
    logs_folder = project_root / "sample_logs"

    datasets = [
        "password_spray.csv",
        "normal_authentication.csv",
        "edge_case.csv",
    ]

    print("=" * 60)
    print("PASSWORD SPRAY DETECTION VALIDATION")
    print("=" * 60)

    print(f"\nThresholds:")
    print(f"Unique users: {UNIQUE_USER_THRESHOLD}")
    print(f"Failed attempts: {FAILED_ATTEMPT_THRESHOLD}")
    print(f"Time window: {WINDOW_MINUTES} minutes")

    for dataset in datasets:

        file_path = logs_folder / dataset

        print("\n" + "-" * 60)
        print(f"Dataset: {dataset}")

        logs = load_logs(file_path)
        alerts = detect_password_spray(logs)

        print(f"Total events: {len(logs)}")

        if alerts:
            print("RESULT: DETECTION TRIGGERED")

            for alert in alerts:
                print(f"Source IP: {alert['source_ip']}")
                print(f"Failed attempts: {alert['failed_attempts']}")
                print(f"Unique users: {alert['unique_users']}")
                print(f"Targeted users: {alert['targeted_users']}")

        else:
            print("RESULT: NO DETECTION")


if __name__ == "__main__":
    main()