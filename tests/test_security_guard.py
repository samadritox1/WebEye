import socket
import unittest
from unittest.mock import patch
from fastapi import HTTPException
from app.core.security_guard import (
    SSRFBlockedError,
    is_private_or_reserved_ip,
    is_public_ip,
    resolve_and_validate_host,
    validate_target_url,
)


class TestSecurityGuard(unittest.TestCase):
    def test_private_ip_detection(self):
        self.assertTrue(is_private_or_reserved_ip("127.0.0.1"))
        self.assertTrue(is_private_or_reserved_ip("10.0.0.1"))
        self.assertTrue(is_private_or_reserved_ip("192.168.1.1"))
        self.assertTrue(is_private_or_reserved_ip("172.16.0.1"))
        self.assertTrue(is_private_or_reserved_ip("169.254.169.254"))
        self.assertTrue(is_private_or_reserved_ip("100.64.0.1"))
        self.assertTrue(is_private_or_reserved_ip("100.100.100.200"))
        self.assertTrue(is_private_or_reserved_ip("192.0.0.192"))
        self.assertTrue(is_private_or_reserved_ip("224.0.0.1"))
        self.assertTrue(is_private_or_reserved_ip("0.0.0.0"))
        self.assertTrue(is_private_or_reserved_ip("::1"))
        self.assertTrue(is_private_or_reserved_ip("fe80::1"))
        self.assertTrue(is_private_or_reserved_ip("fd00:ec2::254"))
        self.assertTrue(is_private_or_reserved_ip("::ffff:127.0.0.1"))
        self.assertTrue(is_private_or_reserved_ip("::ffff:169.254.169.254"))
        self.assertTrue(is_private_or_reserved_ip("64:ff9b::127.0.0.1"))
        self.assertFalse(is_private_or_reserved_ip("8.8.8.8"))
        self.assertFalse(is_private_or_reserved_ip("1.1.1.1"))
        self.assertTrue(is_public_ip("8.8.8.8"))
        self.assertTrue(is_public_ip("2606:4700:4700::1111"))
        self.assertFalse(is_public_ip("100.64.0.1"))
        self.assertFalse(is_public_ip("224.0.0.1"))

    def test_blocked_localhost_scans(self):
        with self.assertRaises(HTTPException) as ctx:
            validate_target_url("http://localhost:8000/api/scans")
        self.assertEqual(ctx.exception.status_code, 400)
        self.assertIn("SSRF Defense", ctx.exception.detail)

        with self.assertRaises(HTTPException) as ctx:
            validate_target_url("http://127.0.0.1:8000")
        self.assertEqual(ctx.exception.status_code, 400)

        with self.assertRaises(HTTPException) as ctx:
            validate_target_url("http://169.254.169.254/latest/meta-data/")
        self.assertEqual(ctx.exception.status_code, 400)

    def test_cloud_metadata_and_internal_hosts_blocked(self):
        targets = [
            "http://169.254.169.254/latest/meta-data/",
            "http://169.254.170.2/v2/credentials/",
            "http://169.254.169.253/",
            "http://169.254.169.123/",
            "http://100.100.100.200/latest/meta-data/",
            "http://192.0.0.192/opc/v2/instance/",
            "http://[fd00:ec2::254]/latest/meta-data/",
            "http://metadata.google.internal/computeMetadata/v1/",
            "http://metadata.goog/",
            "http://metadata/",
            "http://instance-data/",
            "http://service.internal/",
            "http://nas.local/",
            "http://localhost./",
            "http://sub.localhost/",
            "http://localhost.localdomain/",
        ]
        for url in targets:
            with self.subTest(url=url):
                with self.assertRaises(SSRFBlockedError) as ctx:
                    validate_target_url(url)
                self.assertEqual(ctx.exception.status_code, 400)
                self.assertIn("SSRF Defense", ctx.exception.detail)

    def test_obfuscated_ips_and_ipv6_bypasses_blocked(self):
        targets = [
            "http://[::1]:8000/admin",
            "http://[::]/",
            "http://[0:0:0:0:0:0:0:1]/",
            "http://[::ffff:127.0.0.1]/",
            "http://[::ffff:7f00:1]/",
            "http://[::ffff:169.254.169.254]/",
            "http://[::ffff:a9fe:a9fe]/",
            "http://[fe80::1]/",
            "http://[fe80::1%eth0]/",
            "http://[fe80::1%25eth0]/",
            "http://[fc00::1]/",
            "http://[64:ff9b::127.0.0.1]/",
            "http://[2002:7f00:1::]/",
            "http://0x7f000001/",
            "http://0177.0.0.1/",
            "http://2130706433/",
            "http://2852039166/",
            "http://0xa9fea9fe/",
            "http://127.1/",
            "http://0/",
            "http://１２７.０.０.１/",
            "http://ⓛⓞⓒⓐⓛⓗⓞⓢⓣ/",
        ]
        for url in targets:
            with self.subTest(url=url):
                with self.assertRaises(SSRFBlockedError) as ctx:
                    validate_target_url(url)
                self.assertEqual(ctx.exception.status_code, 400)

    def test_schemes_parser_confusions_and_ports_blocked(self):
        bad_urls = [
            "file:///etc/passwd",
            "gopher://127.0.0.1:6379/_INFO",
            "ftp://example.com/file",
            "javascript:alert(1)",
            "data:text/html,<script>alert(1)</script>",
            "http://trusted.com@127.0.0.1/",
            "http://evil.com\\@127.0.0.1/",
            "http://127.0.0.%31/",
            "https://8.8.8.8:6379/",
            "https://8.8.8.8:22/",
            "https://example.com:0/",
            "https://example.com/test\r\nInjected: 1",
        ]
        for url in bad_urls:
            with self.subTest(url=url):
                with self.assertRaises(HTTPException) as ctx:
                    validate_target_url(url)
                self.assertEqual(ctx.exception.status_code, 400)

    def test_dns_resolution_to_private_or_dual_stack_blocked(self):
        # Single private A record
        with patch(
            "app.core.security_guard.socket.getaddrinfo",
            return_value=[(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 443))],
        ):
            with self.assertRaises(SSRFBlockedError):
                validate_target_url("https://rebind.example.com")

        # Dual-stack returning one public IPv4 + one private IPv6/IPv4 -> must block entire host
        with patch(
            "app.core.security_guard.socket.getaddrinfo",
            return_value=[
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443)),
                (socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("fd00:ec2::254", 443, 0, 0)),
            ],
        ):
            with self.assertRaises(SSRFBlockedError):
                resolve_and_validate_host("dualstack.example.com", 443)

        # Dual-stack public IPs -> allowed, IPv4 ordered first
        with patch(
            "app.core.security_guard.socket.getaddrinfo",
            return_value=[
                (socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("2606:4700:4700::1111", 443, 0, 0)),
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("1.1.1.1", 443)),
            ],
        ):
            ips = resolve_and_validate_host("public.example.com", 443)
            self.assertEqual(ips, ["1.1.1.1", "2606:4700:4700::1111"])

    def test_valid_public_urls(self):
        url = validate_target_url("https://example.com")
        self.assertTrue(url.startswith("https://example.com"))

        url2 = validate_target_url("google.com")
        self.assertEqual(url2, "https://google.com")

        url3 = validate_target_url("https://[2606:4700:4700::1111]/")
        self.assertEqual(url3, "https://[2606:4700:4700::1111]/")


if __name__ == "__main__":
    unittest.main()
