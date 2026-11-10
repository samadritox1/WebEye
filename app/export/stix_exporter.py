import uuid
from datetime import datetime, timezone
from typing import Dict, Any, List

class STIX21Exporter:
    @staticmethod
    def _deterministic_uuid(scan_id: str, role: str) -> str:
        if scan_id:
            return str(uuid.uuid5(uuid.NAMESPACE_URL, f"phishpulse:{scan_id}:{role}"))
        return str(uuid.uuid4())

    @staticmethod
    def _escape_stix_literal(val: str) -> str:
        return str(val).replace("\\", "\\\\").replace("'", "\\'")

    @staticmethod
    def generate_stix_bundle(scan_report: Dict[str, Any]) -> Dict[str, Any]:
        """Convert a PhishPulse scan report into a compliant STIX 2.1 Threat Intelligence Bundle."""
        now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        scan_id = str(scan_report.get("scan_id", ""))
        bundle_id = f"bundle--{STIX21Exporter._deterministic_uuid(scan_id, 'bundle')}"
        target_url = scan_report["target_url"]
        domain = scan_report["target_domain"]
        verdict = scan_report["verdict"]
        score = scan_report["overall_score"]
        
        objects: List[Dict[str, Any]] = []

        # 1. Indicator SDO
        indicator_id = f"indicator--{STIX21Exporter._deterministic_uuid(scan_id, 'indicator')}"
        safe_url = STIX21Exporter._escape_stix_literal(target_url)
        safe_domain = STIX21Exporter._escape_stix_literal(domain)
        pattern = f"[url:value = '{safe_url}' OR domain-name:value = '{safe_domain}']"
        # Assign STIX indicator_types labels appropriate to the scan verdict
        if verdict == "MALICIOUS":
            labels = ["malicious-activity", "phishing", "credential-harvesting"]
        elif verdict == "HIGH_RISK":
            labels = ["malicious-activity", "suspicious-site"]
        elif verdict == "SUSPICIOUS":
            labels = ["anomalous-activity"]
        else:
            # BENIGN: include for reference/sighting but not as a threat indicator
            labels = ["benign"]

        indicator_obj = {
            "type": "indicator",
            "spec_version": "2.1",
            "id": indicator_id,
            "created": now_iso,
            "modified": now_iso,
            "name": f"Phishing / Malicious Indicator for {domain}",
            "description": scan_report.get("summary", ""),
            "indicator_types": labels,
            "pattern": pattern,
            "pattern_type": "stix",
            "pattern_version": "2.1",
            "valid_from": now_iso,
            "confidence": int(score)
        }
        objects.append(indicator_obj)

        # 2. Attack Pattern SDOs (Dynamic behavior-mapped MITRE ATT&CK techniques)
        from app.core.mitre_mapper import MitreAttackMapper

        mitre_report = scan_report.get("mitre_attack")
        if not isinstance(mitre_report, dict) or "techniques" not in mitre_report:
            mitre_report = MitreAttackMapper().build_investigation_report(
                scans=[scan_report],
                context_label=f"URL Scan {scan_id}",
                source_id=scan_id,
            )

        mapped_techniques = list(mitre_report.get("techniques") or [])
        has_t1566 = any(t.get("technique_id") == "T1566.002" for t in mapped_techniques)
        if not has_t1566 and (not mapped_techniques or float(scan_report.get("overall_score", scan_report.get("composite_score", 0.0)) or 0.0) >= 40.0):
            mapped_techniques.insert(0, {
                "technique_id": "T1566.002",
                "technique_name": "Phishing: Spearphishing Link",
                "tactic_name": "Initial Access",
                "severity": "medium",
                "confidence": 75.0,
                "mitre_url": "https://attack.mitre.org/techniques/T1566/002/",
                "summary": (
                    "Adversaries may send spearphishing messages with a malicious link in an attempt "
                    "to gain access to victim systems or harvest credentials."
                ),
                "observed_behaviors": [
                    f"URL submission context analyzed for {scan_report.get('target_url', 'target')} "
                    f"(verdict={scan_report.get('verdict', 'UNKNOWN')})."
                ],
                "hunting_pivots": [],
            })

        # Order T1566.002 first so primary external_references[0] in PDF/legacy parsers remains deterministic
        ordered_techniques = sorted(
            mapped_techniques,
            key=lambda item: (0 if item.get("technique_id") == "T1566.002" else 1, item.get("technique_id", "")),
        )

        # Preserve Observed Data / Infrastructure SDO section ordering by keeping attack-pattern creation here,
        # and creating relationship SROs together after indicator/attack-pattern SDOs.
        attack_pattern_links = []
        for tech in ordered_techniques:
            tech_id = tech.get("technique_id") or "T1566.002"
            is_primary = tech_id == "T1566.002"
            ap_seed = "attack-pattern" if is_primary else f"attack-pattern-{tech_id}"
            rel_seed = "relationship" if is_primary else f"relationship-{tech_id}"
            ap_id = f"attack-pattern--{STIX21Exporter._deterministic_uuid(scan_id, ap_seed)}"
            rel_uuid = STIX21Exporter._deterministic_uuid(scan_id, rel_seed)

            evidence_lines = [str(e) for e in (tech.get("observed_behaviors") or tech.get("evidence") or [])[:5]]
            base_desc = tech.get("summary") or tech.get("description") or f"Observed behaviors mapped to MITRE ATT&CK {tech_id}."
            full_desc = base_desc
            if evidence_lines:
                full_desc = f"{base_desc} Observed behaviors: " + "; ".join(evidence_lines)

            tactic_name = tech.get("tactic_name") or "Initial Access"
            tech_name = tech.get("technique_name") or tech.get("name") or tech_id
            sdo_name = (
                "Spearphishing Link (MITRE ATT&CK T1566.002)"
                if is_primary
                else f"{tech_name} (MITRE ATT&CK {tech_id})"
            )
            tech_url = tech.get("mitre_url") or tech.get("url") or f"https://attack.mitre.org/techniques/{tech_id.replace('.', '/')}/"

            attack_pattern_obj = {
                "type": "attack-pattern",
                "spec_version": "2.1",
                "id": ap_id,
                "created": now_iso,
                "modified": now_iso,
                "name": sdo_name,
                "description": full_desc,
                "kill_chain_phases": [
                    {
                        "kill_chain_name": "mitre-attack",
                        "phase_name": tactic_name.lower().replace(" ", "-").replace("&", "and"),
                    }
                ],
                "external_references": [
                    {
                        "source_name": "mitre-attack",
                        "external_id": tech_id,
                        "url": tech_url,
                    }
                ],
                "x_phishpulse_tactic": tactic_name,
                "x_phishpulse_severity": tech.get("severity", "medium"),
                "x_phishpulse_confidence": tech.get("confidence", 80.0),
                "x_phishpulse_evidence": evidence_lines,
                "x_phishpulse_hunting_pivots": list(tech.get("hunting_pivots") or [])[:4],
            }
            objects.append(attack_pattern_obj)
            attack_pattern_links.append((ap_id, rel_uuid, evidence_lines))

        # 3. Infrastructure SDO
        infra_id = f"infrastructure--{STIX21Exporter._deterministic_uuid(scan_id, 'infrastructure')}"
        infra_obj = {
            "type": "infrastructure",
            "spec_version": "2.1",
            "id": infra_id,
            "created": now_iso,
            "modified": now_iso,
            "name": f"Infrastructure for {domain}",
            "infrastructure_types": ["hosting-target", "phishing-landing-page"],
            "aliases": [domain]
        }
        objects.append(infra_obj)

        # 4. Relationship SROs (Indicator indicates each mapped Attack-Pattern)
        for ap_id, rel_uuid, evidence_lines in attack_pattern_links:
            rel_obj = {
                "type": "relationship",
                "spec_version": "2.1",
                "id": f"relationship--{rel_uuid}",
                "created": now_iso,
                "modified": now_iso,
                "relationship_type": "indicates",
                "source_ref": indicator_id,
                "target_ref": ap_id,
            }
            if evidence_lines:
                rel_obj["description"] = "; ".join(evidence_lines[:3])
            objects.append(rel_obj)

        return {
            "type": "bundle",
            "id": bundle_id,
            "objects": objects
        }

    @staticmethod
    def generate_feed_bundle(iocs: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Convert a list of active community IoCs into a collective STIX 2.1 feed bundle."""
        now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        bundle_id = f"bundle--{uuid.uuid4()}"
        objects: List[Dict[str, Any]] = []

        for item in iocs:
            indicator_id = f"indicator--{uuid.uuid4()}"
            ind_val = item["indicator"]
            ind_type = item["indicator_type"]
            
            if ind_type == "url":
                pattern = f"[url:value = '{ind_val}']"
            elif ind_type == "domain":
                pattern = f"[domain-name:value = '{ind_val}']"
            else:
                pattern = f"[ipv4-addr:value = '{ind_val}']"

            obj = {
                "type": "indicator",
                "spec_version": "2.1",
                "id": indicator_id,
                "created": item.get("first_seen", now_iso),
                "modified": item.get("last_seen", now_iso),
                "name": f"Threat IoC: {ind_val}",
                "description": item.get("notes", "Collaborative threat indicator"),
                "indicator_types": ["malicious-activity", "phishing"],
                "pattern": pattern,
                "pattern_type": "stix",
                "pattern_version": "2.1",
                "valid_from": item.get("first_seen", now_iso),
                "confidence": int(item.get("confidence", 85.0))
            }
            objects.append(obj)

        return {
            "type": "bundle",
            "id": bundle_id,
            "objects": objects
        }
