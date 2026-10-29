# Security Log Analyzer

## 1. Project Overview

Security Log Analyzer is a Python-based cybersecurity project that analyzes authentication logs to identify repeated failed login attempts and potentially suspicious IP addresses.

The project uses synthetic log data for safe testing and educational purposes.

## 2. Features

- Reads authentication log files.
- Identifies failed login attempts.
- Groups failed attempts by IP address.
- Flags IP addresses that meet a configurable threshold.
- Generates a Markdown security report.
- Reports invalid timestamps and malformed IP addresses in recognized failed-login entries.
- Includes automated unit tests.

## 3. Technologies Used

- Python 3
- Regular Expressions (re)
- Collections (Counter)
- pathlib
- datetime
- unittest

## 4. Project Structure

```text
security log analyzer/
├── log_analyzer.py
├── test_log_analyzer.py
├── sample_logs.txt
├── README.md
└── reports/
    └── security_report.md
```

## 5. How to Run

Make sure Python 3 is installed.

Open the project folder in VS Code and run:

```bash
python log_analyzer.py
```

## 6. Run Automated Tests

Run:

```bash
python -m unittest test_log_analyzer -v
```

The tests cover repeated failed logins, separate IP counts, successful logins, configurable thresholds, empty files, and invalid timestamps.

## 7. Generated Report

The program generates a Markdown report at:

`reports/security_report.md`

The report summarizes failed login attempts and IP addresses that cross the configured threshold.

## 8. Security Considerations

Repeated failed login attempts can indicate suspicious activity but do not independently prove a brute-force attack.

The tool analyzes local sample data and does not connect to external systems or block IP addresses.

## 9. Limitations

- Detection is based on the total number of failed attempts, not a time window.
- The current implementation uses a local report file.
- It does not automatically block IP addresses.
- It does not guarantee detection of every possible log format.

## 10. Future Improvements

- Add time-window-based detection.
- Support additional authentication log formats.
- Export reports to CSV or JSON.
- Add severity levels and summary statistics.
- Improve validation and error handling.

## 11. Disclaimer

This project is intended for educational cybersecurity analysis using authorized logs and synthetic test data.