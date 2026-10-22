
import unittest

from src.detector import analyze_url


class TestPhishGuard(unittest.TestCase):

    def test_empty_url(self):
        result = analyze_url("")
        self.assertEqual(result["risk"], "UNKNOWN")

    def test_invalid_url(self):
        result = analyze_url("not a valid URL ://")
        self.assertEqual(result["risk"], "INVALID")

    def test_http_url_is_flagged(self):
        result = analyze_url("http://example.com")
        self.assertIn(
            "Uses HTTP instead of HTTPS.",
            result["findings"],
        )

    def test_ip_address_is_flagged(self):
        result = analyze_url("http://192.0.2.1/login")
        self.assertIn(
            "Uses an IP address instead of a domain name.",
            result["findings"],
        )

    def test_sensitive_keyword_is_flagged(self):
        result = analyze_url("https://example.com/login")
        self.assertTrue(
            any("sensitive keywords" in finding
                for finding in result["findings"])
        )

    def test_result_has_expected_fields(self):
        result = analyze_url("https://example.com")

        self.assertIn("url", result)
        self.assertIn("score", result)
        self.assertIn("risk", result)
        self.assertIn("findings", result)

    def test_score_is_within_range(self):
        result = analyze_url("http://192.0.2.1/login")

        self.assertGreaterEqual(result["score"], 0)
        self.assertLessEqual(result["score"], 100) 
    
    def test_malformed_port_is_rejected(self):
        result = analyze_url("https://example.com:abc")
        self.assertEqual(result["risk"], "INVALID")

    def test_missing_hostname_is_rejected(self):
        result = analyze_url("https:///login")
        self.assertEqual(result["risk"], "INVALID")

    def test_whitespace_inside_url_is_rejected(self):
        result = analyze_url("https://example .com")
        self.assertEqual(result["risk"], "INVALID")

    def test_credentials_are_flagged(self):
        result = analyze_url(
            "https://user:password@example.com"
        )
        self.assertIn(
            "Contains embedded URL credentials.",
            result["findings"],
        )


if __name__ == "__main__":
    unittest.main()
