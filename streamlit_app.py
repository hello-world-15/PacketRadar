"""
PacketRadar — PCAP Analyzer (Streamlit deployment)
====================================================

This is a Streamlit front-end for the "PCAP Analyzer" half of PacketRadar.
It reuses the exact same backend engines the FastAPI app uses
(app.parser.packet_parser, app.engines.*, app.report.*) — no logic is
duplicated or reimplemented here, this file only wires those engines up
to a Streamlit UI instead of REST endpoints.

Why not the Live Monitor page too? Live capture needs raw-socket / root
access and a long-lived process — both are unavailable on Streamlit
Community Cloud. See README.md's "Deployment" section for the full
explanation and for how to run Live Monitor locally instead.

Run locally:
    streamlit run streamlit_app.py

Deploy: push this repo to GitHub, then point Streamlit Community Cloud
at this file (see README.md).
"""

from __future__ import annotations

import sys
from datetime import datetime
from pathlib import Path

import pandas as pd
import streamlit as st

# Make the backend package importable (backend/app/...)
BACKEND_DIR = Path(__file__).resolve().parent / "backend"
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from scapy.utils import PcapReader  # noqa: E402

from app.cache.pcap_store import PcapAnalysis  # noqa: E402
from app.engines.pcap_hosts_conversations import compute_hosts_conversations  # noqa: E402
from app.engines.pcap_insights import compute_insights  # noqa: E402
from app.engines.pcap_packet_explorer import paginate_packets  # noqa: E402
from app.engines.pcap_protocol_timeline import compute_protocol_timeline  # noqa: E402
from app.engines.pcap_summary import compute_summary  # noqa: E402
from app.engines.pcap_threat_analysis import analyze_threats  # noqa: E402
from app.models.packet import PacketModel  # noqa: E402
from app.parser.packet_parser import PacketParser  # noqa: E402
from app.report.pdf_generator import generate_pdf  # noqa: E402
from app.report.report_builder import build_report  # noqa: E402

MAX_PACKETS = 200_000  # same safety cap the FastAPI /upload endpoint uses

st.set_page_config(page_title="PacketRadar — PCAP Analyzer", page_icon="📡", layout="wide")

# ---------------------------------------------------------------------------
# Brand styling — reuses the same navy/blue/cyan palette as the PDF report
# (see backend/app/report/styles.py) so the web app and the PDF feel like
# one consistent product instead of two different tools.
# ---------------------------------------------------------------------------
st.markdown(
    """
    <style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap');

    html, body, [class*="css"]  { font-family: 'Inter', sans-serif; }

    :root {
        --pr-navy: #0B1F3A;
        --pr-navy-light: #132C4F;
        --pr-blue: #1B4F9C;
        --pr-blue-light: #3E7CC9;
        --pr-accent: #00B4D8;
        --pr-gray: #5B6472;
        --pr-gray-light: #E7EBF0;
    }

    /* Hero banner */
    .pr-hero {
        background: linear-gradient(120deg, var(--pr-navy) 0%, var(--pr-blue) 65%, var(--pr-accent) 130%);
        padding: 2rem 2.25rem;
        border-radius: 14px;
        margin-bottom: 1.5rem;
        box-shadow: 0 8px 24px rgba(0,0,0,0.25);
    }
    .pr-hero h1 {
        color: #fff;
        font-weight: 800;
        font-size: 2.1rem;
        margin: 0 0 0.35rem 0;
        letter-spacing: -0.02em;
    }
    .pr-hero p {
        color: rgba(255,255,255,0.85);
        font-size: 0.98rem;
        margin: 0;
        max-width: 780px;
    }
    .pr-badge {
        display: inline-block;
        background: rgba(0,180,216,0.18);
        border: 1px solid rgba(0,180,216,0.5);
        color: #7FE3F5;
        font-size: 0.72rem;
        font-weight: 600;
        letter-spacing: 0.04em;
        text-transform: uppercase;
        padding: 0.2rem 0.6rem;
        border-radius: 999px;
        margin-bottom: 0.7rem;
    }

    /* Metric cards */
    div[data-testid="stMetric"] {
        background: var(--pr-navy-light);
        border: 1px solid rgba(255,255,255,0.08);
        border-left: 4px solid var(--pr-accent);
        padding: 0.9rem 1rem 0.7rem 1rem;
        border-radius: 10px;
        box-shadow: 0 2px 8px rgba(0,0,0,0.15);
    }
    div[data-testid="stMetric"] label { color: var(--pr-gray-light) !important; opacity: 0.85; }

    /* Tabs */
    button[data-baseweb="tab"] {
        font-weight: 600;
        font-size: 0.95rem;
    }
    button[data-baseweb="tab"][aria-selected="true"] {
        color: var(--pr-accent) !important;
    }
    div[data-baseweb="tab-highlight"] { background-color: var(--pr-accent) !important; }

    /* Section subheaders get a small accent rule */
    h3 { border-left: 4px solid var(--pr-accent); padding-left: 0.6rem; }

    /* Buttons */
    div.stButton > button, div.stDownloadButton > button {
        background: linear-gradient(90deg, var(--pr-blue) 0%, var(--pr-accent) 100%);
        color: white;
        border: none;
        font-weight: 600;
        border-radius: 8px;
    }
    div.stButton > button:hover, div.stDownloadButton > button:hover {
        filter: brightness(1.08);
        color: white;
    }

    /* Sidebar */
    section[data-testid="stSidebar"] {
        border-right: 1px solid rgba(255,255,255,0.08);
    }
    </style>
    """,
    unsafe_allow_html=True,
)


# ---------------------------------------------------------------------------
# Parsing (mirrors app.api.pcap._parse_and_store, minus the on-disk store)
# ---------------------------------------------------------------------------
@st.cache_data(show_spinner=False)
def parse_pcap_bytes(file_bytes: bytes, filename: str) -> tuple[list[PacketModel], int]:
    """Parses raw .pcap/.pcapng bytes into PacketModels using the exact
    same PacketParser the live capture and FastAPI upload path use."""
    import tempfile

    suffix = Path(filename).suffix.lower() or ".pcap"
    with tempfile.NamedTemporaryFile(suffix=suffix, delete=False) as tmp:
        tmp.write(file_bytes)
        tmp_path = tmp.name

    packets: list[PacketModel] = []
    try:
        with PcapReader(tmp_path) as reader:
            for i, pkt in enumerate(reader):
                if i >= MAX_PACKETS:
                    break
                model = PacketParser.parse(
                    pkt,
                    interface="streamlit-upload",
                    timestamp=datetime.fromtimestamp(float(pkt.time)),
                )
                if model is not None:
                    packets.append(model)
    finally:
        Path(tmp_path).unlink(missing_ok=True)

    return packets, len(file_bytes)


def build_analysis(packets: list[PacketModel], filename: str) -> PcapAnalysis:
    summary = compute_summary(packets)
    return PcapAnalysis(capture_id="streamlit", filename=filename, packets=packets, summary=summary)


# ---------------------------------------------------------------------------
# UI
# ---------------------------------------------------------------------------
st.markdown(
    """
    <div class="pr-hero">
        <span class="pr-badge">PCAP Analyzer</span>
        <h1>📡 PacketRadar</h1>
        <p>Upload a <code>.pcap</code> / <code>.pcapng</code> capture to get Capture Summary,
        DNS Analysis, Threat Detection, Top Hosts &amp; Conversations, Protocol Distribution,
        a Traffic Timeline, a Packet Explorer, and a downloadable PDF report — all computed
        by PacketRadar's real analysis engines.</p>
    </div>
    """,
    unsafe_allow_html=True,
)

with st.sidebar:
    st.header("About this deployment")
    st.markdown(
        "This Streamlit app runs the **PCAP Analyzer** half of PacketRadar only.\n\n"
        "The **Live Monitor** page (real-time packet capture, live threat alerts, "
        "bandwidth graphs) needs raw-socket/root access and a long-running process, "
        "which Streamlit Cloud doesn't provide — run that part locally instead. "
        "See `backend/README.md` for instructions."
    )
    st.markdown("---")
    st.markdown("**Try it without a file:** a bundled sample capture with a full "
                "synthetic attack scenario (ARP spoofing, port scan, SYN flood, DNS "
                "tunneling, beaconing, data exfiltration) is available below.")

use_sample = st.sidebar.checkbox("Use bundled sample capture (attack scenario)", value=False)

uploaded_file = None
if not use_sample:
    uploaded_file = st.file_uploader("Upload a capture file", type=["pcap", "pcapng"])

file_bytes = None
filename = None

if use_sample:
    sample_path = Path(__file__).resolve().parent / "sample_captures" / "demo_attack_scenario.pcap"
    if sample_path.exists():
        file_bytes = sample_path.read_bytes()
        filename = sample_path.name
    else:
        st.error("Sample capture not found in `sample_captures/`.")
elif uploaded_file is not None:
    file_bytes = uploaded_file.getvalue()
    filename = uploaded_file.name

if file_bytes is None:
    st.info("Upload a `.pcap`/`.pcapng` file, or tick the sample-capture box in the sidebar, to begin.")
    st.stop()

with st.spinner("Parsing capture and running analysis engines..."):
    packets, file_size = parse_pcap_bytes(file_bytes, filename)

if not packets:
    st.error("No readable packets were found in this file.")
    st.stop()

analysis = build_analysis(packets, filename)
summary = analysis.summary

st.success(f"Parsed **{len(packets):,}** packets from `{filename}` ({file_size / 1024:.1f} KB).")

tabs = st.tabs(
    [
        "📊 Summary",
        "🌐 DNS Analysis",
        "🚨 Threat Analysis",
        "🖥️ Hosts & Conversations",
        "📈 Protocol & Timeline",
        "🔍 Packet Explorer",
        "📄 PDF Report",
    ]
)

# --- Summary -----------------------------------------------------------
with tabs[0]:
    st.subheader("Capture Summary")
    cols = st.columns(4)
    cols[0].metric("Total Packets", f"{summary.packet_count:,}")
    cols[1].metric("Duration (s)", f"{summary.duration_seconds:.1f}")
    cols[2].metric("Avg Packet Size", f"{summary.avg_packet_size_bytes} B")
    cols[3].metric("Unique Hosts", f"{summary.unique_hosts}")
    cols2 = st.columns(2)
    cols2[0].metric("Connections", f"{summary.connection_count}")
    cols2[1].metric("DNS Requests", f"{summary.dns_request_count}")
    st.json(summary.model_dump(), expanded=False)

# --- DNS Analysis + Threat/Health from /insights -----------------------
with tabs[1]:
    st.subheader("DNS Analysis & Network Health")
    insights = compute_insights(packets)
    st.metric("Network Health Score", f"{insights.health.score}/100")
    if insights.health.factors:
        st.caption(" · ".join(insights.health.factors))
    c1, c2, c3 = st.columns(3)
    with c1:
        st.markdown("**Top Domains**")
        st.dataframe(pd.DataFrame([d.model_dump() for d in insights.dns.top_domains]), use_container_width=True)
    with c2:
        st.markdown("**Repeated Queries**")
        st.dataframe(pd.DataFrame([d.model_dump() for d in insights.dns.repeated_queries]), use_container_width=True)
    with c3:
        st.markdown("**Failed Queries**")
        st.dataframe(pd.DataFrame([d.model_dump() for d in insights.dns.failed_queries]), use_container_width=True)

# --- Threat Analysis (dedicated engine) ---------------------------------
with tabs[2]:
    st.subheader("Threat Analysis")
    threats = analyze_threats(packets)
    if not threats:
        st.success("No threats detected by the Port Scan / ARP Spoofing rules in this capture.")
    else:
        SEVERITY_COLORS = {
            "critical": "#C0392B",
            "high": "#E67E22",
            "medium": "#D4AC0D",
            "low": "#2E8B57",
            "informational": "#5B6472",
        }
        counts = pd.Series([t.severity for t in threats]).value_counts()
        badge_cols = st.columns(len(counts))
        for col, (sev, n) in zip(badge_cols, counts.items()):
            color = SEVERITY_COLORS.get(sev, "#5B6472")
            col.markdown(
                f"""<div style="background:{color}22;border:1px solid {color};
                border-radius:8px;padding:0.5rem;text-align:center;">
                <span style="color:{color};font-weight:700;font-size:1.3rem;">{n}</span><br/>
                <span style="color:{color};font-size:0.75rem;text-transform:uppercase;
                letter-spacing:0.04em;">{sev}</span></div>""",
                unsafe_allow_html=True,
            )
        st.write("")
        threats_df = pd.DataFrame([t.model_dump() for t in threats])

        def _style_severity(row):
            color = SEVERITY_COLORS.get(row["severity"], "#5B6472")
            return [f"background-color: {color}22; color: {color}; font-weight: 600;"
                    if col == "severity" else "" for col in row.index]

        st.dataframe(
            threats_df.style.apply(_style_severity, axis=1),
            use_container_width=True,
        )

# --- Hosts & Conversations ----------------------------------------------
with tabs[3]:
    st.subheader("Top Hosts & Conversations")
    hc = compute_hosts_conversations(packets, summary.duration_seconds)
    c1, c2 = st.columns(2)
    with c1:
        st.markdown("**Top Hosts**")
        st.dataframe(pd.DataFrame([h.model_dump() for h in hc.top_hosts]), use_container_width=True)
    with c2:
        st.markdown("**Conversations**")
        st.dataframe(pd.DataFrame([c.model_dump() for c in hc.conversations]), use_container_width=True)

# --- Protocol Distribution + Timeline ------------------------------------
with tabs[4]:
    st.subheader("Protocol Distribution & Traffic Timeline")
    pt = compute_protocol_timeline(packets)
    c1, c2 = st.columns(2)
    with c1:
        df_proto = pd.DataFrame([p.model_dump() for p in pt.protocol_distribution])
        if not df_proto.empty:
            st.bar_chart(df_proto.set_index("label")["value"])
        st.dataframe(df_proto, use_container_width=True)
    with c2:
        df_timeline = pd.DataFrame([b.model_dump() for b in pt.timeline])
        if not df_timeline.empty:
            st.line_chart(df_timeline.set_index("label"))
        st.dataframe(df_timeline, use_container_width=True)

# --- Packet Explorer ------------------------------------------------------
with tabs[5]:
    st.subheader("Packet Explorer")
    page_size = st.slider("Rows per page", min_value=25, max_value=500, value=100, step=25)
    max_offset = max(len(packets) - 1, 0)
    offset = st.number_input("Offset", min_value=0, max_value=max_offset, value=0, step=page_size)
    page = paginate_packets(packets, offset=int(offset), limit=page_size)
    st.caption(f"Showing {offset}–{offset + len(page.packets)} of {page.total}")
    st.dataframe(pd.DataFrame([p.model_dump() for p in page.packets]), use_container_width=True)

# --- PDF Report -------------------------------------------------------------
with tabs[6]:
    st.subheader("Full PDF Analysis Report")
    st.write(
        "Generates the complete multi-section PacketRadar PDF report — cover page, "
        "executive summary, DNS intelligence, threat findings, host roles, protocol "
        "breakdown, and recommendations — from this capture."
    )
    if st.button("Generate PDF Report", type="primary"):
        with st.spinner("Building report..."):
            report = build_report(analysis, file_size_bytes=file_size)
            pdf_bytes = generate_pdf(report)
        st.download_button(
            "⬇️ Download PDF Report",
            data=pdf_bytes,
            file_name=f"{Path(filename).stem}_report.pdf",
            mime="application/pdf",
        )
        st.success("Report generated.")
