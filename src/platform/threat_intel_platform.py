"""
Threat Intelligence Platform Generator.

Loads IOCs, runs enrichment (with permanent cache) and correlation,
then produces a structured JSON snapshot suitable for downstream SIEM
ingestion or analyst review.

Usage (CLI):
    python -m src.platform --input data/sample_enriched_iocs.json --output examples/platform_snapshot.json
    python -m src.platform --demo 20 --output examples/platform_snapshot.json
"""

import json
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

logger = logging.getLogger(__name__)

PLATFORM_VERSION = "1.0.0"
SOURCE_SYSTEM = "FYP-ThreatIntelBot"


# ── Key-normalization bridge ────────────────────────────────────────────────
# Enrichment uses underscore keys (ioc_value, unified_confidence, …).
# The correlation engine expects no-underscore keys (iocvalue, ioctype, …).

def _normalize_for_correlation(enriched: Dict[str, Any]) -> Dict[str, Any]:
    """Convert enrichment-schema dict to the correlation-engine format."""
    api_raw = enriched.get("api_results") or {}
    api_corr: Dict[str, Any] = {}

    for source, data in api_raw.items():
        if not isinstance(data, dict):
            continue
        nd = dict(data)
        if source == "virustotal":
            nd.setdefault("malicious", nd.get("detections", 0))
            nd.setdefault("detections", nd.get("malicious", 0))
        elif source == "abuseipdb":
            for old_key in ("abuse_confidence_score", "abuseConfidenceScore"):
                if old_key in nd:
                    nd.setdefault("abuseconfidencescore", nd[old_key])
        elif source == "otx":
            nd.setdefault("pulsecount", nd.get("pulse_count", 0))
        elif source == "threatfox":
            for old_key in ("confidence_level", "confidence"):
                if old_key in nd:
                    nd.setdefault("confidencelevel", nd[old_key])
        api_corr[source] = nd

    conf_raw = enriched.get("unified_confidence", 0.0)
    conf = conf_raw / 100.0 if conf_raw > 1.0 else float(conf_raw)

    if conf >= 0.70:
        action = "BLOCK"
    elif conf >= 0.30:
        action = "MONITOR"
    else:
        action = "IGNORE"

    malware = "UNKNOWN"
    tf = api_raw.get("threatfox") or {}
    if tf.get("status") == "success" and tf.get("malware"):
        malware = tf["malware"]

    return {
        "iocvalue": enriched.get("ioc_value", ""),
        "ioctype": (enriched.get("ioc_type") or "").upper(),
        "unifiedconfidence": conf,
        "triageaction": action,
        "apiresults": api_corr,
        "malwarefamily": malware,
        "resolvesto": enriched.get("resolves_to", ""),
        "otxpulses": [],
        "timestamp": enriched.get("timestamp", ""),
    }


# ── IOC array builder ───────────────────────────────────────────────────────

def _build_ioc_entry(enriched: Dict[str, Any], cache_meta: Optional[Dict] = None) -> Dict[str, Any]:
    """Build a single IOC entry for the platform JSON."""
    conf_raw = enriched.get("unified_confidence", 0.0)
    confidence_pct = round(conf_raw * 100, 1) if conf_raw <= 1.0 else round(conf_raw, 1)

    api_results = enriched.get("api_results") or {}
    malware = enriched.get("malware_family", "UNKNOWN")
    if malware == "UNKNOWN":
        tf = api_results.get("threatfox") or {}
        if tf.get("status") == "success" and tf.get("malware"):
            malware = tf["malware"]

    return {
        "ioc_value": enriched.get("ioc_value", ""),
        "ioc_type": (enriched.get("ioc_type") or "").lower(),
        "unified_confidence": confidence_pct,
        "triage_action": enriched.get("triage_action", "IGNORE"),
        "malware_family": malware,
        "resolves_to": enriched.get("resolves_to", None),
        "api_results": api_results,
        "cached_at": cache_meta.get("cached_at") if cache_meta else enriched.get("timestamp"),
        "stale": cache_meta.get("stale", False) if cache_meta else False,
    }


# ── Incident array builder ──────────────────────────────────────────────────

def _build_incident_entry(incident: Dict[str, Any], decision: Optional[Any] = None) -> Dict[str, Any]:
    """Build a single incident entry for the platform JSON."""
    score = incident.get("score") or {}
    severity = score.get("severity_level", "LOW") if isinstance(score, dict) else "LOW"
    risk_score = score.get("final_score", 0) if isinstance(score, dict) else 0
    reasoning = score.get("reasoning", "") if isinstance(score, dict) else ""

    families = incident.get("malware_families", ["UNKNOWN"])
    primary_family = families[0] if families else "UNKNOWN"

    rules = []
    if incident.get("group_size", 0) > 1:
        rules.append("shared_infrastructure")
    if primary_family != "UNKNOWN":
        rules.append("malware_family_group")

    rec_action = "No action needed"
    if decision:
        rec_action = getattr(decision, "reason", str(decision))
    elif severity == "CRITICAL":
        rec_action = f"BLOCK all IOCs immediately — {primary_family} campaign"
    elif severity == "HIGH":
        rec_action = f"Quarantine and investigate — {primary_family} indicators"

    return {
        "incident_id": incident.get("incident_id", "INC-0000"),
        "severity": severity,
        "risk_score": round(float(risk_score), 1),
        "ioc_count": incident.get("group_size", 0),
        "ioc_values": incident.get("ioc_values", []),
        "malware_family": primary_family,
        "rules_matched": rules,
        "recommended_action": rec_action,
        "reasoning": reasoning,
    }


# ── Summary builder ─────────────────────────────────────────────────────────

def _build_summary(iocs: List[Dict], incidents: List[Dict]) -> Dict[str, Any]:
    """Build the top-level summary block."""
    sev_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    families: set = set()

    for inc in incidents:
        sev = inc.get("severity", "LOW")
        sev_counts[sev] = sev_counts.get(sev, 0) + 1
        fam = inc.get("malware_family", "UNKNOWN")
        if fam != "UNKNOWN":
            families.add(fam)

    return {
        "total_iocs": len(iocs),
        "total_incidents": len(incidents),
        "critical_incidents": sev_counts["CRITICAL"],
        "high_incidents": sev_counts["HIGH"],
        "medium_incidents": sev_counts["MEDIUM"],
        "low_incidents": sev_counts["LOW"],
        "campaigns_detected": len(families),
        "unique_malware_families": sorted(families) if families else [],
    }


# ── Main generator ──────────────────────────────────────────────────────────

def generate_platform_json(
    enriched_iocs: List[Dict[str, Any]],
    run_correlation: bool = True,
) -> Dict[str, Any]:
    """
    Generate the full platform JSON snapshot.

    Args:
        enriched_iocs: List of enrichment-output dicts (underscore keys).
        run_correlation: Whether to run the correlation + decision engines.

    Returns:
        Complete platform JSON dict.
    """
    logger.info("Building platform JSON for %d IOCs", len(enriched_iocs))

    # 1. Build IOC array
    ioc_entries = [_build_ioc_entry(e) for e in enriched_iocs]
    logger.info("Built %d IOC entries", len(ioc_entries))

    # 2. Correlation + decisions
    incident_entries: List[Dict] = []
    if run_correlation and enriched_iocs:
        try:
            from src.correlation.engine.engine import correlate_iocs
            corr_input = [_normalize_for_correlation(e) for e in enriched_iocs]
            raw_incidents = correlate_iocs(corr_input)
            logger.info("Correlation produced %d incidents", len(raw_incidents))

            decisions_map: Dict[str, Any] = {}
            try:
                from src.decision import generate_incident_recommendations
                decisions_list, _ = generate_incident_recommendations(raw_incidents)
                decisions_map = {d.incident_id: d for d in decisions_list}
            except Exception as exc:
                logger.warning("Decision engine skipped: %s", exc)

            for inc in raw_incidents:
                dec = decisions_map.get(inc.get("incident_id"))
                incident_entries.append(_build_incident_entry(inc, dec))

        except Exception as exc:
            logger.error("Correlation failed: %s", exc)

    # 3. Summary
    summary = _build_summary(ioc_entries, incident_entries)

    platform = {
        "platform_version": PLATFORM_VERSION,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "source_system": SOURCE_SYSTEM,
        "summary": summary,
        "iocs": ioc_entries,
        "incidents": incident_entries,
    }

    logger.info(
        "Platform JSON ready: %d IOCs, %d incidents, %d campaigns",
        summary["total_iocs"],
        summary["total_incidents"],
        summary["campaigns_detected"],
    )
    return platform


# ── Load helpers ────────────────────────────────────────────────────────────

def load_iocs_from_file(path: str) -> List[Dict[str, Any]]:
    """
    Load IOCs from a JSON file.

    Supports formats:
      - {"iocs": [...]}  (sample_enriched_iocs.json)
      - [...]            (flat list)
      - {"enriched": [...]}
    """
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)

    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        for key in ("iocs", "enriched", "results"):
            if key in data and isinstance(data[key], list):
                return data[key]
    raise ValueError(f"Unrecognised IOC file format in {path}")


def generate_demo_iocs(count: int = 20) -> List[Dict[str, Any]]:
    """Generate demo IOCs via the correlation demo generator, then normalise."""
    from src.correlation.engine.demo_cli import DemoDataGenerator
    raw = DemoDataGenerator.generate_sample_iocs(count)

    enriched = []
    for ioc in raw:
        conf = ioc.get("unifiedconfidence", 0)
        enriched.append({
            "ioc_value": ioc.get("iocvalue", ""),
            "ioc_type": (ioc.get("ioctype") or "").lower(),
            "unified_confidence": conf,
            "triage_action": ioc.get("triageaction", "IGNORE"),
            "api_results": ioc.get("apiresults", {}),
            "malware_family": ioc.get("malwarefamily", "UNKNOWN"),
            "resolves_to": ioc.get("resolvesto", ""),
            "timestamp": ioc.get("timestamp", datetime.now(timezone.utc).isoformat()),
        })
    return enriched


def save_platform_json(platform: Dict[str, Any], path: str) -> None:
    """Write platform JSON to disk."""
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    with open(out, "w", encoding="utf-8") as fh:
        json.dump(platform, fh, indent=2, default=str)
    logger.info("Saved platform JSON to %s", path)
