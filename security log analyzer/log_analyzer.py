import re
from collections import Counter
from pathlib import Path
from datetime import datetime


BASE_DIR = Path(__file__).resolve().parent
LOG_FILE = BASE_DIR / "sample_logs.txt"
REPORT_DIR = BASE_DIR / "reports"

FAILED_PATTERN = re.compile(
    r"(?P<timestamp>\d{4}-\d{2}-\d{2} "
    r"\d{2}:\d{2}:\d{2}) "
    r"FAILED Login attempt from "
    r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
)


def analyze_logs(log_file, threshold=5):
    """Analyze failed login attempts in a sample log file."""

    log_file = Path(log_file)
    failed_attempts = Counter()
    findings = []
    total_lines = 0

    with log_file.open("r", encoding="utf-8") as file:
        for line in file:
            total_lines += 1
            match = FAILED_PATTERN.search(line)

            if not match:
                continue

            timestamp = match.group("timestamp")
            ip = match.group("ip")

            # Validate the timestamp.
            try:
                datetime.strptime(timestamp, "%Y-%m-%d %H:%M:%S")
            except ValueError:
                findings.append(
                    f"Invalid timestamp in log line {total_lines}."
                )
                continue

            # Validate each IPv4 octet.
            octets = ip.split(".")
            if any(not 0 <= int(part) <= 255 for part in octets):
                findings.append(
                    f"Invalid IPv4 address in log line {total_lines}."
                )
                continue

            failed_attempts[ip] += 1

    suspicious_ips = {
        ip: count
        for ip, count in failed_attempts.items()
        if count >= threshold
    }

    return {
        "total_lines": total_lines,
        "failed_attempts": dict(failed_attempts),
        "suspicious_ips": suspicious_ips,
        "findings": findings,
        "threshold": threshold,
    }


def generate_report(results):
    """Generate a Markdown security report."""

    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    report_file = REPORT_DIR / "security_report.md"

    lines = [
        "# Security Log Analysis Report",
        "",
        f"Total log lines analyzed: {results['total_lines']}",
        f"Failed login threshold: {results['threshold']}",
        "",
        "## Failed Login Attempts by IP",
        "",
    ]

    for ip, count in sorted(results["failed_attempts"].items()):
        lines.append(f"- {ip}: {count} failed attempts")

    lines.extend(["", "## Suspicious Activity", ""])

    if results["suspicious_ips"]:
        for ip, count in sorted(results["suspicious_ips"].items()):
            lines.append(
                f"- HIGH: {ip} recorded {count} failed attempts."
            )
    else:
        lines.append("No IP addresses crossed the configured threshold.")

    lines.extend(["", "## Data Quality Findings", ""])

    if results["findings"]:
        lines.extend(f"- {item}" for item in results["findings"])
    else:
        lines.append("No data quality issues detected.")

    lines.extend([
        "",
        "## Important Note",
        "",
        "Repeated failed logins can indicate suspicious activity, "
        "but do not prove an attack. Investigate the surrounding context.",
        "",
    ])

    report_file.write_text(
        "\n".join(lines),
        encoding="utf-8"
    )

    return report_file


def main():
    print("=== Security Log Analyzer ===")

    try:
        results = analyze_logs(LOG_FILE)
    except OSError as error:
        print(f"Could not read the log file: {error}")
        return

    print("\nFailed login attempts:")
    for ip, count in sorted(results["failed_attempts"].items()):
        print(f"{ip}: {count}")

    print("\nSuspicious IP addresses:")
    if results["suspicious_ips"]:
        for ip, count in sorted(results["suspicious_ips"].items()):
            print(f"HIGH: {ip} — {count} failed attempts")
    else:
        print("No suspicious IP addresses found.")

    for finding in results["findings"]:
        print("WARNING:", finding)

    report_file = generate_report(results)
    print(f"\nReport saved to: {report_file}")


if __name__ == "__main__":
    main()