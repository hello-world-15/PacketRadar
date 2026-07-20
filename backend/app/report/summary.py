"""
Executive Summary helpers — turns the Network Health Score into a
risk level/score pair, and writes the one-paragraph narrative.

Risk score is defined as 100 - health score: `compute_health_score`
(app.engines.pcap_insights) already expresses "how healthy does this
capture look", so risk is simply its complement rather than a second,
possibly-diverging heuristic.
"""

from __future__ import annotations

from app.report.report_models import RiskLevel


def risk_level_for_score(risk_score: int) -> RiskLevel:
    if risk_score >= 75:
        return "CRITICAL"
    if risk_score >= 50:
        return "HIGH"
    if risk_score >= 25:
        return "MEDIUM"
    return "LOW"


def build_narrative(
    *,
    packet_count: int,
    unique_hosts: int,
    flow_count: int,
    protocol_count: int,
    finding_count: int,
    risk_level: RiskLevel,
    top_protocol: str,
    duration_desc: str,
) -> str:
    if finding_count == 0:
        finding_clause = (
            "PacketRadar did not identify any notable security findings in this capture."
        )
    else:
        plural = "s" if finding_count != 1 else ""
        finding_clause = (
            f"PacketRadar identified {finding_count} security finding{plural} "
            "that warrant review — see Section 13 for full detail."
        )

    return (
        f"This capture spans {duration_desc} and consists primarily of "
        f"{top_protocol} traffic. PacketRadar observed {packet_count:,} packets "
        f"across {unique_hosts} unique host(s), {flow_count:,} network flow(s), "
        f"and {protocol_count} distinct protocol(s). {finding_clause} "
        f"Based on the combination of threat findings, DNS anomalies, and traffic "
        f"characteristics observed, this capture's overall risk level is "
        f"assessed as {risk_level}."
    )
