#!/usr/bin/env python3
"""
PhishPulse CLI: Command-Line Interface for Cyber Threat Intelligence & Web Security Scanning
"""
import sys
import json
import asyncio
import argparse
from typing import Optional

from app.models.database import init_db, get_all_iocs, add_ioc, get_stats
from app.core.scoring_engine import ScoringEngine
from app.core.security_guard import SSRFBlockedError, validate_target_url
from app.export.stix_exporter import STIX21Exporter
from app.export.pdf_exporter import PDFIncidentReportExporter

def format_color(text: str, color: str) -> str:
    colors = {
        "red": "\033[91m",
        "green": "\033[92m",
        "yellow": "\033[93m",
        "blue": "\033[94m",
        "cyan": "\033[96m",
        "bold": "\033[1m",
        "reset": "\033[0m"
    }
    return f"{colors.get(color, '')}{text}{colors['reset']}"

async def cmd_scan(
    url: str,
    fetch_content: bool,
    deep_dns: bool,
    export_stix: Optional[str] = None,
    export_pdf: Optional[str] = None,
    refresh_intel: bool = False,
):
    print(format_color(f"\n[*] Initiating PhishPulse scan on: {url}", "cyan"))
    try:
        safe_url = validate_target_url(url)
        engine = ScoringEngine()
        report = await engine.execute_scan(
            safe_url,
            fetch_content=fetch_content,
            deep_dns=deep_dns,
            refresh_intel=refresh_intel,
        )
    except SSRFBlockedError as exc:
        print(format_color(f"\n[!] Blocked by SSRF Defense: {exc.detail}", "red"))
        sys.exit(1)
    except Exception as exc:
        print(format_color(f"\n[!] Scan failed: {exc}", "red"))
        sys.exit(1)

    verdict_colors = {
        "MALICIOUS": "red",
        "HIGH_RISK": "yellow",
        "SUSPICIOUS": "yellow",
        "BENIGN": "green"
    }
    v_col = verdict_colors.get(report["verdict"], "bold")

    print("\n" + "=" * 60)
    print(format_color(
        f"  VERDICT: {report['verdict']} (Risk Score: {report['overall_score']}/100 | "
        f"Confidence: {report.get('confidence', 0)}% {report.get('confidence_level', 'MEDIUM')})",
        v_col,
    ))
    print(format_color(f"  Target: {report['target_domain']} [Scan ID: {report['scan_id']}]", "bold"))
    print("=" * 60)
    print(f"Summary: {report['summary']}")
    if report.get("confidence_reason"):
        print(f"Confidence: {report['confidence_reason']}")
    print()

    # Explainable Score Breakdown
    breakdown = report.get("score_breakdown") or []
    print(format_color("[+] Explainable Risk Score Breakdown:", "cyan"))
    if breakdown:
        for item in breakdown:
            pts = item["points"]
            sign = "+" if pts >= 0 else ""
            raw_pts = item.get("raw_points", pts)
            raw_sign = "+" if raw_pts >= 0 else ""
            print(
                f"  • [{item['engine_label']}] {item['label']}: "
                f"{format_color(f'{sign}{pts}', 'red' if pts >= 15 else 'yellow')} "
                f"(raw {raw_sign}{raw_pts})"
            )
    else:
        print("  • No risk penalty factors triggered (0.0/100).")

    # Individual Engine Scores
    engine_scores = report.get("engine_scores") or []
    if engine_scores:
        print(format_color("\n[+] Individual Engine Scores:", "cyan"))
        for eng in engine_scores:
            pct_weight = int(round(eng["weight"] * 100))
            print(
                f"  • {eng['name']}: {eng['score']}/100 "
                f"(weight {pct_weight}% -> +{eng['weighted_score']} pts | "
                f"status: {eng['status']}, confidence: {eng['confidence']}%)"
            )

    # Missing Evidence
    missing = report.get("missing_evidence") or []
    if missing:
        print(format_color("\n[!] Missing Evidence / Uncollected Checks:", "yellow"))
        for gap in missing:
            print(f"  • [{gap['engine']}] {gap['check']}: {gap['reason']} (impact: {gap['impact']})")
    print()

    # Pillar 1
    t = report["threat_analysis"]
    print(format_color("[1] Threat Analysis Engine:", "bold"))
    print(f"  • Score: {t['score']}/100 | Domain Entropy: {t['entropy']} | IP Host: {t['is_ip_domain']}")
    print(f"  • Homoglyph: {t['homoglyph_detected']} | Brand Impersonation: {t['impersonated_brand'] or 'None'}")
    print(f"  • Password Input: {t['has_password_input']} | Cross-Origin Form: {t['has_cross_origin_form']}")
    if t["lexical_flags"]:
        for f in t["lexical_flags"]:
            print(f"    - {format_color(f, 'red' if 'Brand' in f or 'Homoglyph' in f else 'yellow')}")

    # Pillar 2
    s = report["web_security"]
    print(format_color("\n[2] Web Security Assessment:", "bold"))
    print(f"  • Score: {s['score']}/100 | Security Headers Grade: {s['headers_grade']}")
    print(f"  • HSTS: {s['hsts_enabled']} | CSP: {s['csp_enabled']}")
    print(f"  • SPF Status: {s['spf_status']}")
    print(f"  • DMARC Status: {s['dmarc_status']}")
    print(f"  • Resolved Host IP: {s['ip_address'] or 'N/A'}")

    # Pillar 3
    c = report["cert_validation"]
    print(format_color("\n[3] Certificate Validation:", "bold"))
    print(f"  • Score: {c['score']}/100 | Valid: {c['valid']} | Issuer: {c['issuer']}")
    print(f"  • Age: {c['age_days']} days | Days to Expiry: {c['days_until_expiry']} days")
    print(f"  • SAN Mismatch: {c['san_mismatch']} | Free/Automated CA: {c['is_free_automated_ca']}")

    # Pillar 4
    i = report["threat_intel"]
    print(format_color("\n[4] Real-Time Threat Intelligence:", "bold"))
    print(
        f"  • Score: {i['score']}/100 | Cache Hits: {i.get('cache_hits', 0)} | "
        f"Feed Hits: {', '.join(i['feed_hits']) if i['feed_hits'] else 'None'}"
    )
    print(f"  • Community Consensus: {i['community_votes_malicious']} Malicious / {i['community_votes_benign']} Clean")
    providers = i.get("providers") or []
    if providers:
        for p in providers:
            cache_tag = "[CACHED]" if p.get("cached") else "[LIVE]"
            st = str(p.get("status", "clean")).upper()
            st_col = "red" if p.get("matched") else ("green" if st == "CLEAN" else "yellow")
            updated = p.get("last_updated") or "N/A"
            conf = p.get("match_confidence", 0.0)
            prov = p.get("provenance") or p.get("summary") or ""
            print(
                f"    - {p['source']}: {format_color(st, st_col)} {cache_tag} "
                f"| Conf: {conf}% | Updated: {updated}"
            )
            if prov:
                print(f"      Provenance: {prov}")
    else:
        print(f"  • URLhaus: {i.get('urlhaus_status') or 'Clean'}")

    # Mitigations
    if report["mitigations"]:
        print(format_color("\n[+] Recommended Mitigations:", "cyan"))
        for m in report["mitigations"]:
            print(f"  ▶ {m}")

    # STIX Export
    stix_bundle = None
    if export_stix or export_pdf:
        stix_bundle = STIX21Exporter.generate_stix_bundle(report)

    if export_stix and stix_bundle is not None:
        with open(export_stix, "w", encoding="utf-8") as f:
            json.dump(stix_bundle, f, indent=2)
        print(format_color(f"\n[✓] STIX 2.1 Threat Bundle exported to: {export_stix}", "green"))

    # PDF Incident Report Export
    if export_pdf:
        pdf_bytes = PDFIncidentReportExporter.generate_pdf_report(report, stix_bundle=stix_bundle)
        with open(export_pdf, "wb") as f:
            f.write(pdf_bytes)
        print(format_color(f"\n[✓] PDF Incident Report exported to: {export_pdf}", "green"))

def main():
    init_db()
    parser = argparse.ArgumentParser(description="PhishPulse Cyber Threat Intelligence CLI")
    subparsers = parser.add_subparsers(dest="command", help="Commands")

    # scan command
    p_scan = subparsers.add_parser("scan", help="Scan a target URL or domain")
    p_scan.add_argument("url", help="URL or domain to analyze")
    p_scan.add_argument("--no-content", action="store_true", help="Skip live DOM fetching")
    p_scan.add_argument("--no-dns", action="store_true", help="Skip DNS SPF/DMARC resolution")
    p_scan.add_argument("--refresh-intel", action="store_true", help="Bypass CTI cache and query live feeds")
    p_scan.add_argument("--stix", help="Filepath to export STIX 2.1 bundle")
    p_scan.add_argument("--pdf", help="Filepath to export PDF incident report")

    # iocs command
    p_iocs = subparsers.add_parser("iocs", help="List active Collaborative Threat IoCs")
    p_iocs.add_argument("--limit", type=int, default=20, help="Max items to list")

    # stats command
    subparsers.add_parser("stats", help="Show platform telemetry & metrics")

    args = parser.parse_args()

    if args.command == "scan":
        asyncio.run(cmd_scan(
            url=args.url,
            fetch_content=not args.no_content,
            deep_dns=not args.no_dns,
            export_stix=args.stix,
            export_pdf=args.pdf,
            refresh_intel=args.refresh_intel,
        ))
    elif args.command == "iocs":
        iocs = get_all_iocs(limit=args.limit)
        print(format_color(f"\nActive Collaborative Threat Indicators ({len(iocs)}):", "cyan"))
        print("-" * 75)
        for ioc in iocs:
            print(f"[{ioc['id']}] {ioc['indicator']} | Type: {ioc['indicator_type']} | Source: {ioc['source']}")
            print(f"    Tags: {', '.join(ioc['tags'])} | Consensus: +{ioc['votes_malicious']} / -{ioc['votes_benign']}")
        print("-" * 75)
    elif args.command == "stats":
        stats = get_stats()
        print(format_color("\nPhishPulse Platform Telemetry:", "cyan"))
        for k, v in stats.items():
            print(f"  {k.replace('_', ' ').title()}: {v}")
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
