#!/usr/bin/env python3
"""
Threat Intel Platform Dashboard (Standalone Streamlit App)

Run:
    streamlit run scripts/dashboard.py

Requirements:
    pip install streamlit plotly pandas
"""

from __future__ import annotations

import asyncio
import json
import secrets
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Tuple, Callable

import pandas as pd
import streamlit as st


st.set_page_config(
    page_title="Automated Threat Intel Platform",
    layout="wide",
)

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_SNAPSHOT = PROJECT_ROOT / "output" / "platform_snapshot.json"
WAZUH_SCRIPT = PROJECT_ROOT / "scripts" / "generate_wazuh_logs.py"
WAZUH_RULES = PROJECT_ROOT / "wazuh_integration" / "local_rules.xml"
AUTH_KEYS_FILE = PROJECT_ROOT / "output" / "auth_keys.json"
PLATFORM_IP = "localhost"

# Ensure `src` imports work regardless of streamlit launch directory
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


def _safe_read_text(path: Path) -> str:
    """Read a text file safely for code display."""
    if not path.exists():
        return f"# File not found: {path}"
    try:
        return path.read_text(encoding="utf-8")
    except OSError as exc:
        return f"# Could not read {path}: {exc}"


def _load_json_file(path: Path) -> Any:
    """Load JSON from a path and return parsed object."""
    with path.open("r", encoding="utf-8") as fh:
        return json.load(fh)


def _safe_read_snapshot(path: Path) -> Dict[str, Any] | None:
    """Load platform snapshot JSON safely. Returns None on error."""
    if not path.exists():
        st.error(
            f"Snapshot file not found: `{path}`\n\n"
            "Generate it first, e.g. `python -m src.platform --demo 20 --output output/platform_snapshot.json`."
        )
        return None

    try:
        with path.open("r", encoding="utf-8") as fh:
            data = json.load(fh)
    except json.JSONDecodeError as exc:
        st.error(f"Invalid JSON in `{path}`: {exc}")
        return None
    except OSError as exc:
        st.error(f"Could not read `{path}`: {exc}")
        return None

    if not isinstance(data, dict):
        st.error("Snapshot JSON must be an object at top-level.")
        return None

    return data


def _normalize_frames(snapshot: Dict[str, Any]) -> Tuple[pd.DataFrame, pd.DataFrame, Dict[str, Any]]:
    """Build incidents/iocs DataFrames and summary object from snapshot."""
    incidents_raw = snapshot.get("incidents") or []
    iocs_raw = snapshot.get("iocs") or []
    summary = snapshot.get("summary") or {}

    if not isinstance(incidents_raw, list):
        incidents_raw = []
    if not isinstance(iocs_raw, list):
        iocs_raw = []
    if not isinstance(summary, dict):
        summary = {}

    incidents_df = pd.DataFrame(incidents_raw)
    iocs_df = pd.DataFrame(iocs_raw)

    for col, default in [
        ("incident_id", ""),
        ("severity", "UNKNOWN"),
        ("malware_family", "Unknown"),
        ("risk_score", 0),
    ]:
        if col not in incidents_df.columns:
            incidents_df[col] = default

    for col, default in [
        ("ioc_value", ""),
        ("ioc_type", "unknown"),
        ("malware_family", "Unknown"),
        ("unified_confidence", 0),
        ("triage_action", "IGNORE"),
    ]:
        if col not in iocs_df.columns:
            iocs_df[col] = default

    incidents_df["severity"] = incidents_df["severity"].astype(str).str.upper()
    incidents_df["malware_family"] = incidents_df["malware_family"].replace({"UNKNOWN": "Unknown"})

    iocs_df["ioc_type"] = iocs_df["ioc_type"].astype(str).str.lower()
    iocs_df["triage_action"] = iocs_df["triage_action"].astype(str).str.upper()
    iocs_df["malware_family"] = iocs_df["malware_family"].replace({"UNKNOWN": "Unknown"})

    return incidents_df, iocs_df, summary


def _df_to_csv_bytes(df: pd.DataFrame) -> bytes:
    """Convert dataframe to CSV bytes for st.download_button."""
    return df.to_csv(index=False).encode("utf-8")


def _classify_ioc(ioc_value: str) -> str:
    """Simple IOC type classifier used by search/upload flows."""
    v = ioc_value.strip()
    if v.startswith("http://") or v.startswith("https://"):
        return "URL"
    if len(v) in (32, 40, 64) and all(ch in "0123456789abcdefABCDEF" for ch in v):
        return "hash"
    parts = v.split(".")
    if len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
        return "IP"
    return "domain"


def _run_maybe_async(fn: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
    """Execute function whether it is sync or async."""
    result = fn(*args, **kwargs)
    if asyncio.iscoroutine(result):
        return asyncio.run(result)
    return result


def _import_backend_functions() -> Tuple[Callable[[str, str], Dict[str, Any]], Callable[[List[Dict[str, Any]]], Dict[str, Any]]]:
    """
    Import real backend functions with robust fallbacks.

    Returns:
        enrich_single_fn(ioc_value, ioc_type) -> enriched IOC dict
        pipeline_fn(ioc_batch) -> platform JSON dict
    """
    enrich_single_fn = None
    pipeline_fn = None

    # Enrichment single IOC
    try:
        from src.enrichment.api import enrich_single as _enrich_single
        enrich_single_fn = _enrich_single
    except Exception:
        try:
            from src.enrichment.enrichment import IOCEnricher
            _enricher = IOCEnricher()
            enrich_single_fn = _enricher.enrich_ioc
        except Exception as exc:
            raise ImportError(f"Could not import enrichment backend: {exc}") from exc

    # Full pipeline from enriched list -> platform snapshot
    try:
        from src.platform.threat_intel_platform import generate_platform_json as _gen_platform
        pipeline_fn = _gen_platform
    except Exception as exc:
        raise ImportError(f"Could not import platform pipeline backend: {exc}") from exc

    return enrich_single_fn, pipeline_fn


def _parse_uploaded_iocs(uploaded_file: Any) -> List[str]:
    """Parse uploaded txt/csv file into IOC lines."""
    raw = uploaded_file.getvalue().decode("utf-8", errors="ignore")
    lines = [line.strip() for line in raw.splitlines() if line.strip()]
    if uploaded_file.name.lower().endswith(".csv"):
        parsed: List[str] = []
        for line in lines:
            parts = [p.strip() for p in line.split(",") if p.strip()]
            parsed.extend(parts)
        lines = parsed
    return lines


def _render_ioc_upload_panel() -> None:
    """Render IOC upload and simulated processing controls."""
    st.sidebar.header("IOC Upload")
    uploaded_file = st.sidebar.file_uploader(
        "Upload raw IOCs (.txt or .csv)",
        type=["txt", "csv"],
        accept_multiple_files=False,
    )

    if uploaded_file is None:
        st.sidebar.caption("No file uploaded.")
        return

    iocs = _parse_uploaded_iocs(uploaded_file)
    st.sidebar.info(f"Detected {len(iocs)} IOC line(s).")

    if st.sidebar.button("Process IOCs", use_container_width=True):
        st.sidebar.write("Enriching IOCs via Bot Engine...")
        progress = st.sidebar.progress(0)
        for step in range(1, 101, 10):
            time.sleep(0.05)
            progress.progress(step)
        st.sidebar.success("IOCs submitted to the enrichment queue")


def _build_incident_table(incidents_df: pd.DataFrame) -> pd.DataFrame:
    """Return standardized incident table columns."""
    incident_table = incidents_df[["incident_id", "severity", "malware_family", "risk_score"]].copy()
    return incident_table.rename(
        columns={
            "incident_id": "Incident ID",
            "severity": "Severity",
            "malware_family": "Malware Family",
            "risk_score": "Risk Score",
        }
    )


def _build_ioc_table(iocs_df: pd.DataFrame) -> pd.DataFrame:
    """Return standardized IOC table columns."""
    ioc_table = iocs_df[["ioc_value", "ioc_type", "malware_family", "unified_confidence", "triage_action"]].copy()
    return ioc_table.rename(
        columns={
            "ioc_value": "IOC Value",
            "ioc_type": "Type",
            "malware_family": "Malware Family",
            "unified_confidence": "Confidence Score",
            "triage_action": "Triage Action",
        }
    )


def _load_api_keys() -> List[str]:
    """Load persisted API keys from local json file."""
    if not AUTH_KEYS_FILE.exists():
        return []
    try:
        data = _load_json_file(AUTH_KEYS_FILE)
        if isinstance(data, dict) and isinstance(data.get("keys"), list):
            return [str(k) for k in data["keys"] if k]
    except Exception:
        return []
    return []


def _save_api_keys(keys: List[str]) -> None:
    """Persist generated API keys to local json file."""
    AUTH_KEYS_FILE.parent.mkdir(parents=True, exist_ok=True)
    with AUTH_KEYS_FILE.open("w", encoding="utf-8") as fh:
        json.dump({"keys": keys}, fh, indent=2)


def _safe_int(val: Any, default: int = 0) -> int:
    try:
        return int(val)
    except (TypeError, ValueError):
        return default


def _render_detailed_osint_reports(result: Dict[str, Any]) -> None:
    """
    Present api_results from live enrichment using readable Streamlit widgets.
    Falls back safely when providers omit keys or return errors / not_found.
    """
    st.subheader("Detailed OSINT Reports")
    api_results = result.get("api_results")
    if not isinstance(api_results, dict):
        st.info("No structured API results to display.")
        return

    tf_block = api_results.get("threatfox")
    tf_block = tf_block if isinstance(tf_block, dict) else {}
    malware_hint = (
        result.get("malware_family")
        or tf_block.get("malware_printable")
        or tf_block.get("malware")
    )

    col_vt, col_ab, col_otx, col_tf = st.columns(4)

    with col_vt:
        st.markdown("##### VirusTotal")
        vt = api_results.get("virustotal")
        if not isinstance(vt, dict):
            st.caption("No VirusTotal payload.")
        else:
            status = str(vt.get("status") or "unknown")
            if status != "success":
                st.warning(vt.get("error") or f"Status: {status}")
            else:
                dets = _safe_int(vt.get("detections"), 0)
                total = _safe_int(vt.get("total_engines"), 0)
                st.metric("Engines flagged", f"{dets} / {total}")
                if dets > 0:
                    st.error(f"{dets} engine(s) flagged this IOC as malicious.")
                else:
                    st.success("No malicious detections from VirusTotal engines.")
                if malware_hint:
                    st.caption("Malware family (best available)")
                    st.write(str(malware_hint))

    with col_ab:
        st.markdown("##### AbuseIPDB")
        ab = api_results.get("abuseipdb")
        if ab is None:
            st.caption("Not queried (IP-only source).")
        elif not isinstance(ab, dict):
            st.caption("Unexpected AbuseIPDB payload shape.")
        else:
            status = str(ab.get("status") or "unknown")
            if status != "success":
                st.warning(ab.get("error") or f"Status: {status}")
            else:
                score = _safe_int(ab.get("abuse_confidence_score"), 0)
                score = max(0, min(score, 100))
                st.caption("Abuse confidence score")
                st.progress(score / 100.0)
                st.metric("Score", f"{score}/100")
                if ab.get("is_whitelisted"):
                    st.success("Marked as whitelisted by AbuseIPDB.")
                raw = ab.get("raw_data") if isinstance(ab.get("raw_data"), dict) else {}
                data_block = raw.get("data") if isinstance(raw.get("data"), dict) else {}
                country_code = data_block.get("countryCode") or ab.get("countryCode") or "—"
                country_name = ab.get("country") or data_block.get("countryName") or ""
                isp = ab.get("isp") or "—"
                st.write(f"**Country code:** {country_code}")
                if country_name:
                    st.caption(country_name)
                st.write(f"**ISP:** {isp}")

    with col_otx:
        st.markdown("##### OTX (AlienVault)")
        otx = api_results.get("otx")
        if not isinstance(otx, dict):
            st.caption("No OTX payload.")
        else:
            status = str(otx.get("status") or "unknown")
            if status != "success":
                st.warning(otx.get("error") or f"Status: {status}")
            else:
                pulses = _safe_int(otx.get("pulse_count"), 0)
                st.metric("Linked pulses", pulses)
                st.info(f"OTX reports **{pulses}** community pulse(s) referencing this IOC.")
                names = otx.get("pulses")
                if isinstance(names, list) and names:
                    preview = ", ".join(str(n) for n in names[:5] if n)
                    if preview:
                        st.caption("Sample pulse names")
                        st.write(preview + ("…" if len(names) > 5 else ""))

    with col_tf:
        st.markdown("##### ThreatFox")
        tf = api_results.get("threatfox")
        if not isinstance(tf, dict):
            st.caption("No ThreatFox payload.")
        else:
            status = str(tf.get("status") or "unknown")
            if status == "not_found":
                st.info("No ThreatFox record for this IOC.")
            elif status != "success":
                st.warning(tf.get("error") or f"Status: {status}")
            else:
                conf = _safe_int(tf.get("confidence_level"), 0)
                ioc_n = _safe_int(tf.get("ioc_count"), 0)
                st.metric("Confidence level", f"{conf}/100")
                st.metric("Matching IOC entries", ioc_n)
                st.info("ThreatFox confidence reflects campaign / malware context for this indicator.")


def main() -> None:
    st.title("Automated Threat Intel Platform")
    st.caption("Enterprise-style frontend for live enrichment, pipeline processing, and SIEM integration")

    snapshot = _safe_read_snapshot(DEFAULT_SNAPSHOT)
    if snapshot is None:
        st.stop()

    incidents_df, iocs_df, summary = _normalize_frames(snapshot)

    # Sidebar: upload + filters + platform JSON download
    _render_ioc_upload_panel()

    st.sidebar.download_button(
        "Download Platform JSON",
        data=json.dumps(snapshot, indent=2).encode("utf-8"),
        file_name="platform_snapshot.json",
        mime="application/json",
        use_container_width=True,
    )

    if "searched_iocs" not in st.session_state:
        st.session_state["searched_iocs"] = []

    searched_iocs = st.session_state["searched_iocs"]
    searched_count = len(searched_iocs)
    block_count = sum(1 for row in searched_iocs if str(row.get("triage_action", "")).upper() == "BLOCK")
    monitor_count = sum(1 for row in searched_iocs if str(row.get("triage_action", "")).upper() == "MONITOR")

    c1, c2, c3 = st.columns(3)
    c1.metric("Searched IOCs", f"{searched_count}")
    c2.metric("BLOCK Recommendations", f"{block_count}")
    c3.metric("MONITOR Recommendations", f"{monitor_count}")

    tabs = st.tabs(
        [
            "IOC Search",
            "Upload",
            "IOCs",
            "API Gateway",
            "SIEM Integration",
        ]
    )

    with tabs[0]:
        st.subheader("Live IOC Search (Real Enrichment)")
        ioc_input_col, type_col = st.columns([3, 1])
        with ioc_input_col:
            ioc_value = st.text_input("IOC Value", placeholder="e.g. 8.8.8.8, evil-domain.com, https://bad.url/path")
        with type_col:
            ioc_type = st.selectbox("IOC Type", options=["Auto", "IP", "domain", "URL", "hash"], index=0)

        if st.button("Search & Enrich", use_container_width=False):
            parsed_iocs = [part.strip() for part in ioc_value.split(",") if part.strip()]
            if not parsed_iocs:
                st.warning("Please enter at least one IOC value.")
            else:
                try:
                    enrich_single_fn, _ = _import_backend_functions()
                except Exception as exc:
                    st.error(f"Live enrichment initialization failed: {exc}")
                    enrich_single_fn = None

                if enrich_single_fn is not None:
                    with st.spinner("Querying OSINT APIs..."):
                        for idx, current_ioc in enumerate(parsed_iocs, start=1):
                            with st.expander(f"IOC {idx}: {current_ioc}", expanded=True):
                                resolved_type = _classify_ioc(current_ioc) if ioc_type == "Auto" else ioc_type
                                try:
                                    result = _run_maybe_async(enrich_single_fn, current_ioc, resolved_type)
                                    if not isinstance(result, dict):
                                        st.error("Unexpected enrichment response format.")
                                        continue

                                    c1, c2, c3 = st.columns(3)
                                    conf_raw = float(result.get("unified_confidence", 0))
                                    conf_pct = conf_raw * 100 if conf_raw <= 1 else conf_raw
                                    c1.metric("Confidence Score", f"{conf_pct:.1f}")
                                    c2.metric("Triage Action", str(result.get("triage_action", "UNKNOWN")))
                                    c3.metric("IOC Type", str(result.get("ioc_type", "UNKNOWN")).upper())

                                    api_results = result.get("api_results", {})
                                    if isinstance(api_results, dict):
                                        errors = []
                                        for src, payload in api_results.items():
                                            if isinstance(payload, dict) and payload.get("status") == "error":
                                                err_msg = payload.get("error") or "error"
                                                errors.append(f"{src}: {err_msg}")
                                        if errors:
                                            st.warning("Some providers failed: " + "; ".join(errors))

                                    _render_detailed_osint_reports(result)

                                    raw_payload = api_results if isinstance(api_results, dict) else {"api_results": api_results}
                                    with st.expander("View Raw JSON Data"):
                                        st.json(raw_payload)

                                    searched_row = {
                                        "ioc_value": current_ioc,
                                        "ioc_type": str(result.get("ioc_type", resolved_type)).lower(),
                                        "malware_family": str(result.get("malware_family", "Unknown")),
                                        "unified_confidence": float(result.get("unified_confidence", 0) or 0),
                                        "triage_action": str(result.get("triage_action", "UNKNOWN")).upper(),
                                    }
                                    searched_iocs.append(searched_row)
                                    st.session_state["searched_iocs"] = searched_iocs
                                except Exception as exc:
                                    st.error(f"IOC `{current_ioc}` failed: {exc}")
                            st.divider()

    with tabs[1]:
        st.subheader("Real File Upload & Processing")
        uploaded = st.file_uploader(
            "Upload IOC file (.txt or .csv)",
            type=["txt", "csv"],
            accept_multiple_files=False,
            key="upload_tab_file",
        )

        parsed_iocs: List[str] = []
        if uploaded is not None:
            parsed_iocs = _parse_uploaded_iocs(uploaded)
            st.info(f"Loaded {len(parsed_iocs)} IOC(s) from `{uploaded.name}`.")

        if st.button("Process", use_container_width=False, disabled=(uploaded is None)):
            if not parsed_iocs:
                st.warning("No valid IOCs found in uploaded file.")
            else:
                try:
                    enrich_single_fn, pipeline_fn = _import_backend_functions()
                    enriched_results: List[Dict[str, Any]] = []
                    progress = st.progress(0)
                    status = st.empty()

                    total = len(parsed_iocs)
                    for idx, value in enumerate(parsed_iocs, start=1):
                        status.write(f"Processing {idx}/{total}: `{value}`")
                        inferred = _classify_ioc(value)
                        enriched = _run_maybe_async(enrich_single_fn, value, inferred)
                        if isinstance(enriched, dict):
                            enriched_results.append(enriched)
                        progress.progress(int(idx / total * 100))

                    with st.spinner("Running correlation and platform JSON generation..."):
                        platform_result = _run_maybe_async(pipeline_fn, enriched_results, True)

                    if not isinstance(platform_result, dict):
                        st.error("Pipeline returned unexpected format.")
                    else:
                        status.success("Pipeline complete.")
                        incidents = platform_result.get("incidents") or []
                        incidents_df_new = pd.DataFrame(incidents if isinstance(incidents, list) else [])
                        if incidents_df_new.empty:
                            st.info("No incidents produced from uploaded IOC set.")
                        else:
                            for col, default in [("incident_id", ""), ("severity", "UNKNOWN"), ("malware_family", "Unknown"), ("risk_score", 0)]:
                                if col not in incidents_df_new.columns:
                                    incidents_df_new[col] = default
                            st.markdown("#### Generated Incidents")
                            st.dataframe(_build_incident_table(incidents_df_new), use_container_width=True)
                except Exception as exc:
                    st.error(f"Processing pipeline failed: {exc}")

    with tabs[2]:
        st.subheader("IOCs")
        if searched_iocs:
            searched_df = pd.DataFrame(searched_iocs)
            ioc_table = _build_ioc_table(searched_df)
        else:
            ioc_table = pd.DataFrame(columns=["IOC Value", "Type", "Malware Family", "Confidence Score", "Triage Action"])
            st.info("No searched IOCs yet. Use the IOC Search tab to enrich and populate this table.")

        dl_col, info_col = st.columns([1, 3])
        with dl_col:
            st.download_button(
                "Download CSV",
                data=_df_to_csv_bytes(ioc_table),
                file_name="searched_iocs.csv",
                mime="text/csv",
                use_container_width=True,
            )
        with info_col:
            st.caption(f"{len(ioc_table)} searched IOC row(s)")

        st.dataframe(ioc_table, use_container_width=True)

    with tabs[3]:
        st.subheader("API Gateway")
        st.markdown("Generate and manage API keys for SIEM/API consumers.")

        keys = _load_api_keys()
        key_col, info_col = st.columns([1, 2])
        with key_col:
            if st.button("Generate New API Key", use_container_width=True):
                new_key = secrets.token_hex(16)
                keys.append(new_key)
                _save_api_keys(keys)
                st.session_state["latest_api_key"] = new_key
        with info_col:
            st.info(
                "Use this API Key in your SIEM (like Wazuh) to authenticate "
                "against this Threat Intel Platform's REST API."
            )

        latest_key = st.session_state.get("latest_api_key") or (keys[-1] if keys else None)
        if latest_key:
            st.markdown("#### Current API Key")
            st.code(latest_key, language="text")
            st.markdown("#### SIEM Pull Command (Dynamic)")
            st.code(
                f'curl -H "x-api-key: {latest_key}" http://{PLATFORM_IP}:8000/api/v1/intel',
                language="bash",
            )
        else:
            st.caption("No API key generated yet.")

        with st.expander("Stored API Keys (local auth_keys.json)"):
            if keys:
                st.write(f"{len(keys)} key(s) stored in `{AUTH_KEYS_FILE}`")
                st.dataframe(pd.DataFrame({"api_key": keys}))
            else:
                st.caption("No saved keys.")

    with tabs[4]:
        st.subheader("SIEM Integration (API/Scripts)")
        st.markdown(
            "This platform can be integrated with SIEM tooling such as **Wazuh** or **Splunk** "
            "using JSON log shipping or API pull patterns."
        )

        with st.expander("Python Script: generate_wazuh_logs.py", expanded=False):
            st.code(_safe_read_text(WAZUH_SCRIPT), language="python")

        with st.expander("Wazuh Rules: local_rules.xml", expanded=False):
            st.code(_safe_read_text(WAZUH_RULES), language="xml")

        st.subheader("REST API (Mock)")
        st.code(
            'curl -X GET "http://localhost:8000/api/v1/incidents" -H "Authorization: Bearer YOUR_TOKEN"',
            language="bash",
        )


if __name__ == "__main__":
    main()

