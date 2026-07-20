"""
Generates the Recommendations section from the same findings already
computed for Security Findings — no separate heuristic pass over raw
packets, so recommendations can never mention a finding that isn't
also listed in Section 13.
"""

from __future__ import annotations

from app.report.report_models import Recommendation, SecurityFinding

_CATEGORY_PRIORITY = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}


def build_recommendations(
    findings: list[SecurityFinding],
    *,
    cleartext_pct: float = 0.0,
    dns_failure_count: int = 0,
) -> list[Recommendation]:
    recs: list[Recommendation] = []
    seen_hosts: set[str] = set()

    for f in sorted(findings, key=lambda x: _CATEGORY_PRIORITY.get(x.severity, 5)):
        if f.affected_host and f.affected_host not in seen_hosts:
            seen_hosts.add(f.affected_host)
            recs.append(Recommendation(
                priority=f.severity,
                text=f"Investigate host {f.affected_host} — flagged for {f.category}. {f.recommendation}",
            ))

    if dns_failure_count > 5:
        recs.append(Recommendation(
            priority="medium",
            text=(
                f"Review the {dns_failure_count} failed DNS lookup(s) observed in this "
                "capture — repeated resolution failures can indicate misconfiguration, "
                "stale records, or malware attempting to reach unregistered domains."
            ),
        ))

    if cleartext_pct > 10:
        recs.append(Recommendation(
            priority="medium",
            text=(
                f"{cleartext_pct:.0f}% of TCP traffic in this capture used plaintext "
                "application ports (21/23/80/110/143). Verify whether encrypted "
                "alternatives (SFTP, SSH, HTTPS, IMAPS) are available and enforce "
                "their use where possible."
            ),
        ))

    if not findings:
        recs.append(Recommendation(
            priority="low",
            text=(
                "No security findings were generated for this capture. Continue "
                "routine monitoring and periodic PCAP review as part of standard "
                "network hygiene."
            ),
        ))

    recs.append(Recommendation(
        priority="low",
        text="Review firewall rules for any hosts or services flagged above and confirm they match intended network policy.",
    ))

    return recs
