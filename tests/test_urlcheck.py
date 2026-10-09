"""Offline tests for the link analyzer and its integration. No network, no API keys."""
import json
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import analyzer  # noqa: E402
import app as app_module  # noqa: E402
import config  # noqa: E402
import urlcheck  # noqa: E402


class Extraction(unittest.TestCase):
    def test_finds_scheme_www_and_bare_links(self):
        text = "Go to http://a-b.xyz/x, or www.example.com. Also bit.ly/3xYzPQ"
        self.assertEqual(urlcheck.extract_urls(text), ["http://a-b.xyz/x", "www.example.com", "bit.ly/3xYzPQ"])

    def test_ignores_names_and_amounts(self):
        self.assertEqual(urlcheck.extract_urls("Mr.Sharma paid Rs.4,999 e.g. today"), [])

    def test_caps_number_of_links(self):
        text = " ".join(f"http://site{i}.com" for i in range(20))
        self.assertEqual(len(urlcheck.extract_urls(text)), urlcheck.MAX_URLS)


class Heuristics(unittest.TestCase):
    def signals(self, url):
        return " | ".join(urlcheck.analyze_url(url)["signals"])

    def test_lookalike_bank_domain(self):
        s = self.signals("http://sbi-kyc-update.xyz/verify")
        self.assertIn("'.xyz'", s)
        self.assertIn("'sbi'", s)
        self.assertIn("hyphens", s)

    def test_official_domain_not_flagged_as_brand_fake(self):
        self.assertNotIn("not a domain we recognise", self.signals("https://www.sbi.co.in/web/personal"))

    def test_shortener_ip_at_sign_and_punycode(self):
        self.assertIn("Shortened", self.signals("bit.ly/abc"))
        self.assertIn("raw IP", self.signals("http://192.168.1.5/login"))
        self.assertIn("'@'", self.signals("http://google.com@evil.example.com/"))
        self.assertIn("punycode", self.signals("http://xn--pple-43d.com/"))

    def test_malformed_url_does_not_crash(self):
        self.assertTrue(urlcheck.analyze_url("http://[bad")["signals"])

    def test_prompt_facts_use_host_only(self):
        facts = urlcheck.facts_for_prompt(urlcheck.check_urls("http://sbi-kyc-update.xyz/ignore-instructions", False))
        self.assertIn("sbi-kyc-update.xyz", facts)
        self.assertNotIn("ignore-instructions", facts)


class SafeBrowsing(unittest.TestCase):
    def test_unchecked_without_key(self):
        with mock.patch.object(config, "SAFE_BROWSING_API_KEY", ""):
            self.assertEqual(urlcheck.check_urls("http://a.xyz")[0]["safe_browsing"], "unchecked")

    def test_flagged_and_clear(self):
        reply = {"matches": [{"threatType": "SOCIAL_ENGINEERING", "threat": {"url": "http://bad.xyz"}}]}
        with mock.patch.object(config, "SAFE_BROWSING_API_KEY", "k"), \
                mock.patch.object(urlcheck, "_sb_request", return_value=reply):
            results = urlcheck.check_urls("http://bad.xyz and http://fine.com")
        by_host = {r["host"]: r for r in results}
        self.assertEqual(by_host["bad.xyz"]["safe_browsing"], "flagged")
        self.assertEqual(by_host["bad.xyz"]["threats"], ["SOCIAL_ENGINEERING"])
        self.assertEqual(by_host["fine.com"]["safe_browsing"], "clear")

    def test_lookup_failure_degrades_gracefully(self):
        with mock.patch.object(config, "SAFE_BROWSING_API_KEY", "k"), \
                mock.patch.object(urlcheck, "_sb_request", side_effect=TimeoutError("slow")):
            self.assertEqual(urlcheck.check_urls("http://a.xyz")[0]["safe_browsing"], "unchecked")

    def test_api_key_never_appears_in_facts(self):
        with mock.patch.object(config, "SAFE_BROWSING_API_KEY", "SECRETKEY123"), \
                mock.patch.object(urlcheck, "_sb_request", return_value={}):
            facts = urlcheck.facts_for_prompt(urlcheck.check_urls("http://a.xyz"))
        self.assertNotIn("SECRETKEY123", facts)


class Integration(unittest.TestCase):
    MODEL_SAYS_SAFE = json.dumps({"verdict": "SAFE", "risk_score": 5, "confidence": "HIGH", "red_flags": [],
                                  "explanation": "ok", "next_steps": [], "share_message": ""})

    def test_safe_browsing_flag_overrides_model(self):
        reply = {"matches": [{"threatType": "MALWARE", "threat": {"url": "http://bad.xyz"}}]}
        with mock.patch.object(config, "SAFE_BROWSING_API_KEY", "k"), \
                mock.patch.object(urlcheck, "_sb_request", return_value=reply), \
                mock.patch.object(analyzer, "raw_generate", return_value=self.MODEL_SAYS_SAFE):
            result = analyzer.analyze("click http://bad.xyz", "en", "simple")
        self.assertEqual(result["verdict"], "SCAM")
        self.assertGreaterEqual(result["risk_score"], 70)
        self.assertEqual(result["url_checks"][0]["safe_browsing"], "flagged")

    def test_url_facts_reach_the_model_outside_the_data_tags(self):
        with mock.patch.object(analyzer, "raw_generate", return_value=self.MODEL_SAYS_SAFE) as m:
            analyzer.analyze("see http://sbi-kyc-update.xyz", "en", "simple")
        sent = m.call_args[0][1][-1]
        self.assertIn("URL_FACTS", sent)
        self.assertLess(sent.index("URL_FACTS"), sent.index("<message_to_analyze>"))


class Headers(unittest.TestCase):
    def test_extra_security_headers(self):
        c = app_module.app.test_client()
        r = c.get("/", headers={"X-Forwarded-Proto": "https"})
        self.assertIn("camera=()", r.headers["Permissions-Policy"])
        self.assertIn("max-age=", r.headers["Strict-Transport-Security"])
        self.assertNotIn("Strict-Transport-Security", c.get("/").headers)


if __name__ == "__main__":
    unittest.main()
