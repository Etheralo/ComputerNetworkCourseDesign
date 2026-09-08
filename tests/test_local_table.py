from pathlib import Path
import tempfile
import unittest

from src.dns_relay.local_table import LocalTable


class LocalTableTests(unittest.TestCase):
    def test_matching_is_case_insensitive_and_ignores_trailing_dot(self):
        table = LocalTable({"local.test": "10.0.0.123"})
        self.assertEqual(table.lookup("LOCAL.Test."), "10.0.0.123")

    def test_loader_accepts_comments_and_rejects_ipv6(self):
        with tempfile.TemporaryDirectory() as directory:
            valid = Path(directory, "valid.txt")
            valid.write_text("# comment\n10.1.2.3 demo.test # inline\n", encoding="utf-8")
            self.assertEqual(LocalTable.load(valid).lookup("demo.test"), "10.1.2.3")
            invalid = Path(directory, "invalid.txt")
            invalid.write_text("::1 demo.test\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "only IPv4"):
                LocalTable.load(invalid)


if __name__ == "__main__":
    unittest.main()
