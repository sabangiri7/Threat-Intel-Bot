"""
Phase 5 - Streamlit SOC Dashboard (entrypoint)

Run:
  streamlit run dashboard/app.py
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Tuple

# Ensure project root is on path so "reports" package is found when running streamlit run dashboard/app.py
_project_root = Path(__file__).resolve().parent.parent
if str(_project_root) not in sys.path:
    sys.path.insert(0, str(_project_root))

import pandas as pd
import plotly.express as px
import streamlit as st

# PDF generator (reportlab required); uses generate_pdf_bytes for current dashboard data
try:
    from reports.pdfgenerator import generate_pdf_bytes as _generate_pdf_bytes
    _has_pdf = True
except Exception:
    _has_pdf = False


DEFAULT_DATA_PATH = "reports/incident_recommendations.json"


@st.cache_data(show_spinner=False)
def load_artifact(path_str: str) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], Dict[str, Any]]:
    """
    Loads dashboard artifact.

    Preferred JSON shape:
      {"incidents": [...], "decisions": [...], "recommendation_summary": {...}}

    Backward compatible:
      [ ...incidents... ]  (list only)
    """
    path = Path(path_str)

    if not path.exists():
        raise FileNotFoundError(f"Artifact not found: {path}")

    with path.open("r", encoding="utf-8") as f:
        data = json.load(f)

    # Preferred (dict)
    if isinstance(data, dict):
        incidents = data.get("incidents", []) or []
        decisions = data.get("decisions", []) or []
        summary = data.get("recommendation_summary", {}) or {}
        return incidents, decisions, summary

    # Backward compatible (list of incidents)
    if isinstance(data, list):
        return data, [], {}

    raise ValueError("Unsupported JSON format: expected dict or list.")


def normalize_incidents(incidents: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Adds UI helper fields so the rest of the dashboard can use one shape:
      _final_score, _severity
    NOTE: incident['score'] is a dict in this repo (final_score, severity_level, breakdown...). [file:3]
    """
    normalized: List[Dict[str, Any]] = []

    for inc in incidents:
        score = inc.get("score") or {}
        final_score = float(score.get("final_score", 0.0))
        severity = score.get("severity_level", "UNKNOWN")

        inc2 = dict(inc)
        inc2["_final_score"] = final_score
        inc2["_severity"] = severity
        normalized.append(inc2)

    return normalized


def main() -> None:
    st.set_page_config(page_title="Threat Intelligence SOC Dashboard", layout="wide")

    st.title("Threat Intelligence SOC Dashboard")
    st.caption("Phase 5 – Visual Dashboard (Streamlit)")

    with st.sidebar:
        st.header("Data")
        data_path = st.text_input("Artifact path", value=DEFAULT_DATA_PATH)

        st.markdown("Generate demo artifact:")
        st.code(
            "python -m src.correlation.engine.demo_cli --iocs 20 --output reports/incident_recommendations.json",
            language="bash",
        )

        if st.button("Reload"):
            load_artifact.clear()
            st.rerun()

    try:
        incidents, decisions, summary = load_artifact(data_path)
    except Exception as e:
        st.error(str(e))
        st.stop()

    incidents = normalize_incidents(incidents)

    st.success(f"Loaded {len(incidents)} incidents")

    # --- KPI row ---
    total_incidents = len(incidents)
    critical_count = sum(1 for i in incidents if i.get("_severity") == "CRITICAL")
    avg_risk = (
        sum(float(i.get("_final_score", 0.0)) for i in incidents) / total_incidents
        if total_incidents else 0.0
    )
    correlated_iocs = sum(int(i.get("group_size", 0) or 0) for i in incidents)

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Total Incidents", total_incidents)
    c2.metric("Critical Count", critical_count)
    c3.metric("Avg Risk Score", f"{avg_risk:.1f}")
    c4.metric("Correlated IOCs", correlated_iocs)

    st.divider()

    # --- Tabs shell ---
    tab_overview, tab_incidents, tab_analysis, tab_recs = st.tabs(
        ["Overview", "Incidents", "Analysis", "Recommendations"]
    )

    with tab_overview:
        st.subheader("Overview")

        col_left, col_right = st.columns(2)

        # Severity distribution (pie)
        with col_left:
            sev_counts: Dict[str, int] = {}
            for inc in incidents:
                sev = inc.get("_severity", "UNKNOWN")
                sev_counts[sev] = sev_counts.get(sev, 0) + 1

            df_sev = pd.DataFrame(
                [{"Severity": k, "Count": v} for k, v in sorted(sev_counts.items())]
            )

            fig_sev = px.pie(
                df_sev,
                names="Severity",
                values="Count",
                title="Severity Distribution",
            )
            st.plotly_chart(fig_sev, use_container_width=True)

        # Risk score distribution (histogram)
        with col_right:
            scores = [float(i.get("_final_score", 0.0)) for i in incidents]
            df_scores = pd.DataFrame({"Risk Score": scores})

            fig_scores = px.histogram(
                df_scores,
                x="Risk Score",
                nbins=20,
                title="Risk Score Distribution",
            )
            st.plotly_chart(fig_scores, use_container_width=True)

    with tab_incidents:
        st.subheader("Incidents")

        # --- Filters ---
        all_sev = sorted({i.get("_severity", "UNKNOWN") for i in incidents})
        default_sev = [s for s in ["CRITICAL", "HIGH"] if s in all_sev] or all_sev

        f1, f2, f3 = st.columns(3)
        with f1:
            sev_filter = st.multiselect("Severity", options=all_sev, default=default_sev)
        with f2:
            min_score = st.slider("Min risk score", 0.0, 100.0, 50.0, 0.5)
        with f3:
            family_query = st.text_input("Malware family contains", value="")

        # --- Apply filters ---
        filtered = incidents

        if sev_filter:
            filtered = [i for i in filtered if i.get("_severity") in sev_filter]

        filtered = [i for i in filtered if float(i.get("_final_score", 0.0)) >= float(min_score)]

        if family_query.strip():
            q = family_query.strip().lower()
            def families_text(inc: dict) -> str:
                fams = inc.get("malware_families") or []
                return ", ".join([str(x) for x in fams]).lower()

            filtered = [i for i in filtered if q in families_text(i)]

        st.caption(f"Showing {len(filtered)} / {len(incidents)} incidents")

        # --- Table ---
        df = pd.DataFrame(
            [
                {
                    "Incident ID": i.get("incident_id"),
                    "Severity": i.get("_severity"),
                    "Risk Score": float(i.get("_final_score", 0.0)),
                    "Group Size": int(i.get("group_size", 0) or 0),
                    "Families": ", ".join(i.get("malware_families") or []),
                    "IOC Types": ", ".join(i.get("ioc_types") or []),
                }
                for i in filtered
            ]
        )

        st.dataframe(df, use_container_width=True)

        # --- CSV export ---
        csv_bytes = df.to_csv(index=False).encode("utf-8")
        st.download_button(
            "Download CSV",
            data=csv_bytes,
            file_name="incidents_filtered.csv",
            mime="text/csv",
        )

    with tab_analysis:
        st.subheader("Analysis")

        col1, col2 = st.columns(2)

        # Top malware families (weighted by group_size like the Phase-5 spec example)
        with col1:
            fam_counts = {}
            for inc in incidents:
                fams = inc.get("malware_families") or []
                weight = int(inc.get("group_size", 1) or 1)
                for fam in fams:
                    if not fam or str(fam).upper() == "UNKNOWN":
                        continue
                    fam_counts[fam] = fam_counts.get(fam, 0) + weight

            if fam_counts:
                top = sorted(fam_counts.items(), key=lambda x: x[1], reverse=True)[:10]
                df_fam = pd.DataFrame(top, columns=["Family", "IOC Count"])
                fig_fam = px.bar(
                    df_fam,
                    x="Family",
                    y="IOC Count",
                    title="Top Malware Families",
                )
                st.plotly_chart(fig_fam, use_container_width=True)
            else:
                st.info("No malware family data (all UNKNOWN).")

        # IOC type distribution (also weighted by group_size)
        with col2:
            type_counts = {}
            for inc in incidents:
                types = inc.get("ioc_types") or []
                weight = int(inc.get("group_size", 1) or 1)
                for t in types:
                    if not t:
                        continue
                    type_counts[t] = type_counts.get(t, 0) + weight

            if type_counts:
                df_types = pd.DataFrame(
                    [{"IOC Type": k, "Count": v} for k, v in sorted(type_counts.items())]
                )
                fig_types = px.pie(
                    df_types,
                    names="IOC Type",
                    values="Count",
                    title="IOC Type Distribution",
                )
                st.plotly_chart(fig_types, use_container_width=True)
            else:
                st.info("No IOC type data found.")

    with tab_recs:
        st.subheader("Recommendations")

        # --- Summary metrics (from JSON) ---
        if isinstance(summary, dict) and summary:
            c1, c2, c3, c4 = st.columns(4)
            c1.metric("BLOCK", int(summary.get("block_count", 0) or 0))
            c2.metric("QUARANTINE", int(summary.get("quarantine_count", 0) or 0))
            c3.metric("MONITOR", int(summary.get("monitor_count", 0) or 0))
            c4.metric("IGNORE", int(summary.get("ignore_count", 0) or 0))

            if summary.get("immediate_action_required", False):
                st.warning("Immediate action required (BLOCK/QUARANTINE present).")

            if summary.get("analyst_review_recommended", False):
                st.info("Analyst review recommended (MONITOR present).")
        else:
            st.info("No recommendation_summary found in the artifact.")

        st.divider()

        # --- Decisions table (from JSON decisions) ---
        if decisions:
            df_dec = pd.DataFrame(
                [
                    {
                        "Incident ID": d.get("incident_id") or d.get("incidentid"),
                        "Recommendation": d.get("recommendation"),
                        "Confidence": d.get("confidence"),
                        "Reason": d.get("reason"),
                    }
                    for d in decisions
                ]
            )
            st.dataframe(df_dec, use_container_width=True)

            csv_bytes = df_dec.to_csv(index=False).encode("utf-8")
            st.download_button(
                "Download decisions CSV",
                data=csv_bytes,
                file_name="decisions.csv",
                mime="text/csv",
            )
        else:
            st.info("No decisions found in the artifact.")

        # --- Report downloads (Phase 6) ---
        st.divider()
        st.subheader("Report downloads")
        decisions_by_id = {str(d.get("incident_id") or d.get("incidentid", "")): d for d in (decisions or [])}

        # Full JSON report
        full_report = {
            "incidents": incidents,
            "decisions": decisions,
            "recommendation_summary": summary,
        }
        json_bytes = json.dumps(full_report, indent=2, ensure_ascii=False).encode("utf-8")
        st.download_button(
            "Download full JSON report",
            data=json_bytes,
            file_name="threat_report.json",
            mime="application/json",
            key="dl_json",
        )

        # PDF report: generate from current data, or serve CLI-generated file
        pdf_path = _project_root / "reports" / "threat_report.pdf"
        if _has_pdf:
            try:
                pdf_bytes = _generate_pdf_bytes(incidents, decisions, summary or {})
                st.download_button(
                    "Download PDF report",
                    data=pdf_bytes,
                    file_name="threat_report.pdf",
                    mime="application/pdf",
                    key="dl_pdf",
                )
            except Exception as e:
                if pdf_path.exists():
                    st.download_button(
                        "Download PDF report",
                        data=pdf_path.read_bytes(),
                        file_name=pdf_path.name,
                        mime="application/pdf",
                        key="dl_pdf",
                    )
                    st.caption("Serving pre-generated PDF. Run `python reports/pdfgenerator.py` to refresh.")
                else:
                    st.caption(f"PDF export unavailable: {e}")
        else:
            if pdf_path.exists():
                st.download_button(
                    "Download PDF report",
                    data=pdf_path.read_bytes(),
                    file_name=pdf_path.name,
                    mime="application/pdf",
                    key="dl_pdf",
                )
                st.caption("Serving pre-generated PDF. Run `python reports/pdfgenerator.py` to refresh.")
            else:
                st.info("Generate the PDF first: run `python reports/pdfgenerator.py` (Phase 6).")

        # Combined CSV (incidents + decisions joined by incident_id)
        rows = []
        for inc in incidents:
            inc_id = str(inc.get("incident_id", ""))
            dec = decisions_by_id.get(inc_id) or {}
            rows.append({
                "Incident ID": inc_id,
                "Severity": inc.get("_severity", ""),
                "Risk Score": float(inc.get("_final_score", 0.0)),
                "Group Size": int(inc.get("group_size", 0) or 0),
                "Families": ", ".join(inc.get("malware_families") or []),
                "IOC Types": ", ".join(inc.get("ioc_types") or []),
                "Recommendation": dec.get("recommendation", ""),
                "Confidence": dec.get("confidence", ""),
                "Reason": dec.get("reason", ""),
            })
        df_combined = pd.DataFrame(rows)
        combined_csv = df_combined.to_csv(index=False).encode("utf-8")
        st.download_button(
            "Download combined CSV",
            data=combined_csv,
            file_name="incidents_and_decisions.csv",
            mime="text/csv",
            key="dl_combined_csv",
        )


if __name__ == "__main__":
    main()
