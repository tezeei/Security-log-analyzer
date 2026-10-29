import tempfile
import unittest
from pathlib import Path

from log_analyzer import analyze_logs


class TestSecurityLogAnalyzer(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.log_file = Path(self.temp_dir.name) / "test_logs.txt"

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_detects_repeated_failed_logins(self):
        self.log_file.write_text(
            "2026-10-27 10:00:00 FAILED Login attempt from 203.0.113.5\n"
            "2026-10-27 10:01:00 FAILED Login attempt from 203.0.113.5\n"
            "2026-10-27 10:02:00 FAILED Login attempt from 203.0.113.5\n"
            "2026-10-27 10:03:00 FAILED Login attempt from 203.0.113.5\n"
            "2026-10-27 10:04:00 FAILED Login attempt from 203.0.113.5\n",
            encoding="utf-8",
        )

        result = analyze_logs(self.log_file)

        self.assertEqual(
            result["failed_attempts"]["203.0.113.5"], 5
        )
        self.assertIn("203.0.113.5", result["suspicious_ips"])

    def test_counts_different_ips_separately(self):
        self.log_file.write_text(
            "2026-10-27 10:00:00 FAILED Login attempt from 203.0.113.5\n"
            "2026-10-27 10:01:00 FAILED Login attempt from 198.51.100.7\n",
            encoding="utf-8",
        )

        result = analyze_logs(self.log_file)

        self.assertEqual(
            result["failed_attempts"]["203.0.113.5"], 1
        )
        self.assertEqual(
            result["failed_attempts"]["198.51.100.7"], 1
        )

    def test_successful_login_is_not_counted_as_failed(self):
        self.log_file.write_text(
            "2026-10-27 10:00:00 INFO Login successful from 192.168.1.10\n",
            encoding="utf-8",
        )

        result = analyze_logs(self.log_file)

        self.assertEqual(result["failed_attempts"], {})
        self.assertEqual(result["suspicious_ips"], {})

    def test_threshold_can_be_changed(self):
        self.log_file.write_text(
            "2026-10-27 10:00:00 FAILED Login attempt from 203.0.113.5\n"
            "2026-10-27 10:01:00 FAILED Login attempt from 203.0.113.5\n",
            encoding="utf-8",
        )

        result = analyze_logs(self.log_file, threshold=2)

        self.assertIn("203.0.113.5", result["suspicious_ips"])

    def test_empty_log_file(self):
        self.log_file.write_text("", encoding="utf-8")

        result = analyze_logs(self.log_file)

        self.assertEqual(result["total_lines"], 0)
        self.assertEqual(result["failed_attempts"], {})
        self.assertEqual(result["suspicious_ips"], {})

    def test_invalid_timestamp_is_reported(self):
        self.log_file.write_text(
            "2026-99-27 10:00:00 FAILED Login attempt from 203.0.113.5\n",
            encoding="utf-8",
        )

        result = analyze_logs(self.log_file)

        self.assertEqual(result["failed_attempts"], {})
        self.assertTrue(result["findings"])


if __name__ == "__main__":
    unittest.main()