"""
PDF Generator — Report Object -> PacketRadar PCAP Analysis PDF.

This module is the only consumer of `app.report.report_models.Report`.
It never touches a `PacketModel` or a raw capture file — everything it
needs is already on the `Report` object handed to `generate_pdf()`.

Built with ReportLab (BaseDocTemplate + a custom onPage callback for the
header/footer/page-number chrome) and Matplotlib (via charts.py) for the
data visualizations.
"""

from __future__ import annotations

import io

from reportlab.lib.pagesizes import A4
from reportlab.lib.units import mm
from reportlab.platypus import (
    BaseDocTemplate,
    FrameBreak,
    KeepTogether,
    NextPageTemplate,
    PageBreak,
    PageTemplate,
    Paragraph,
    Frame,
    Spacer,
    Table,
    TableStyle,
)

from app.report import charts
from app.report.report_models import Report
from app.report.styles import (
    ACCENT,
    BLUE,
    GRAY,
    GRAY_DARK,
    GRAY_LIGHT,
    GRAY_LIGHTER,
    MARGIN,
    NAVY,
    PAGE_SIZE,
    STYLES,
    WHITE,
)
from app.report.tables import severity_badge, styled_table

PAGE_W, PAGE_H = PAGE_SIZE
CONTENT_W = PAGE_W - 2 * MARGIN

TOC_SECTIONS = [
    "Executive Summary", "Capture Information", "Traffic Overview",
    "Network Host Discovery", "Top Talkers", "Flow Analysis",
    "Protocol Analysis", "Port Analysis", "DNS Intelligence",
    "Timeline Analysis", "Security Findings", "Alerts Summary",
    "Recommendations", "Appendix",
]


# ---------------------------------------------------------------------------
# Page chrome: header, footer, page numbers (skipped on the cover page)
# ---------------------------------------------------------------------------


def _draw_chrome(canvas, doc, title: str):
    canvas.saveState()
    # Header
    canvas.setFillColor(NAVY)
    canvas.rect(0, PAGE_H - 14 * mm, PAGE_W, 14 * mm, fill=1, stroke=0)
    canvas.setFillColor(WHITE)
    canvas.setFont("Helvetica-Bold", 10)
    canvas.drawString(MARGIN, PAGE_H - 9.5 * mm, "PacketRadar")
    canvas.setFont("Helvetica", 8.5)
    canvas.setFillColor(GRAY_LIGHT)
    canvas.drawRightString(PAGE_W - MARGIN, PAGE_H - 9.5 * mm, "PCAP Analysis Report")

    # Footer
    canvas.setStrokeColor(GRAY_LIGHT)
    canvas.setLineWidth(0.5)
    canvas.line(MARGIN, 12 * mm, PAGE_W - MARGIN, 12 * mm)
    canvas.setFont("Helvetica", 8)
    canvas.setFillColor(GRAY)
    canvas.drawString(MARGIN, 8 * mm, "Confidential — PacketRadar Automated Analysis")
    canvas.drawRightString(PAGE_W - MARGIN, 8 * mm, f"Page {doc.page}")
    canvas.restoreState()


def _cover_page(canvas, doc):
    canvas.saveState()
    canvas.setFillColor(NAVY)
    canvas.rect(0, 0, PAGE_W, PAGE_H, fill=1, stroke=0)
    canvas.setFillColor(colors_accent_bar := ACCENT)
    canvas.rect(0, PAGE_H - 6 * mm, PAGE_W, 6 * mm, fill=1, stroke=0)
    canvas.restoreState()


def _make_onpage(title: str):
    def _fn(canvas, doc):
        if doc.page == 1:
            _cover_page(canvas, doc)
        else:
            _draw_chrome(canvas, doc, title)
    return _fn


# ---------------------------------------------------------------------------
# Small building blocks
# ---------------------------------------------------------------------------


def _section_heading(number: int, title: str):
    bar = Table([[""]], colWidths=[4], rowHeights=[20])
    bar.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), BLUE),
        ("LEFTPADDING", (0, 0), (-1, -1), 0),
        ("RIGHTPADDING", (0, 0), (-1, -1), 0),
        ("TOPPADDING", (0, 0), (-1, -1), 0),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
    ]))
    heading = Table(
        [[bar, Paragraph(f"{number}. {title}", STYLES["SectionHeading"])]],
        colWidths=[8, CONTENT_W - 8],
    )
    heading.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (0, 0), 0),
        ("RIGHTPADDING", (0, 0), (0, 0), 0),
        ("LEFTPADDING", (1, 0), (1, 0), 8),
        ("RIGHTPADDING", (1, 0), (1, 0), 0),
        ("TOPPADDING", (0, 0), (-1, -1), 0),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
    ]))
    return heading


def _stat_cards(cards, per_row: int = 4):
    flowables = []
    card_w = CONTENT_W / per_row
    rows = [cards[i:i + per_row] for i in range(0, len(cards), per_row)]
    for row in rows:
        cells = []
        for c in row:
            inner = Table(
                [[Paragraph(c.value, STYLES["CardValue"])], [Paragraph(c.label.upper(), STYLES["CardLabel"])]],
                colWidths=[card_w - 8],
            )
            inner.setStyle(TableStyle([
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                ("ALIGN", (0, 0), (-1, -1), "CENTER"),
            ]))
            wrapper = Table([[inner]], colWidths=[card_w])
            wrapper.setStyle(TableStyle([
                ("BOX", (0, 0), (-1, -1), 0.75, GRAY_LIGHT),
                ("BACKGROUND", (0, 0), (-1, -1), GRAY_LIGHTER),
                ("TOPPADDING", (0, 0), (-1, -1), 10),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
                ("LEFTPADDING", (0, 0), (-1, -1), 4),
                ("RIGHTPADDING", (0, 0), (-1, -1), 4),
            ]))
            cells.append(wrapper)
        while len(cells) < per_row:
            cells.append(Spacer(card_w, 1))
        row_table = Table([cells], colWidths=[card_w] * per_row)
        row_table.setStyle(TableStyle([("LEFTPADDING", (0, 0), (-1, -1), 3),
                                        ("RIGHTPADDING", (0, 0), (-1, -1), 3)]))
        flowables.append(row_table)
        flowables.append(Spacer(1, 6))
    return flowables


def _pairs_table(pairs, headers=("Item", "Count")):
    return styled_table(list(headers), [(a, str(b)) for a, b in pairs],
                         col_widths=[CONTENT_W * 0.75, CONTENT_W * 0.25], align=[None, "right"])


# ---------------------------------------------------------------------------
# Section content builders — each returns a list of flowables
# ---------------------------------------------------------------------------


def _cover_content(report: Report):
    story = []
    story.append(Spacer(1, 55 * mm))
    logo_row = Table(
        [[Paragraph("&#9679;", STYLES["CoverTitle"]), Paragraph("PacketRadar", STYLES["CoverTitle"])]],
        colWidths=[14 * mm, CONTENT_W - 14 * mm],
    )
    logo_row.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "MIDDLE")]))
    story.append(logo_row)
    story.append(Spacer(1, 4))
    story.append(Paragraph(report.metadata.report_title, STYLES["CoverSubtitle"]))
    story.append(Spacer(1, 40 * mm))

    meta_rows = [
        ("File", report.metadata.filename),
        ("Generated", report.metadata.generated_at),
        ("Capture Duration", report.metadata.capture_duration),
        ("Version", report.metadata.packetradar_version),
        ("Author", report.metadata.author),
    ]
    for label, value in meta_rows:
        story.append(Paragraph(f"<b>{label}:</b> {value}", STYLES["CoverMeta"]))
        story.append(Spacer(1, 3))

    story.append(Spacer(1, 20 * mm))
    story.append(Paragraph(report.metadata.confidentiality_notice, STYLES["CoverMeta"]))
    return story


def _toc_content():
    story = [_section_heading(0, "Table of Contents"), Spacer(1, 10)]
    rows = [[Paragraph(f"{i}. {name}", STYLES["TocEntry"]), ""] for i, name in enumerate(TOC_SECTIONS, start=1)]
    t = Table(rows, colWidths=[CONTENT_W - 20 * mm, 20 * mm])
    t.setStyle(TableStyle([
        ("LINEBELOW", (0, 0), (-1, -2), 0.4, GRAY_LIGHT),
        ("TOPPADDING", (0, 0), (-1, -1), 4), ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    story.append(t)
    return story


def _executive_summary_content(report: Report):
    s = report.summary
    story = [_section_heading(1, "Executive Summary"), Spacer(1, 10)]
    story.extend(_stat_cards(s.cards, per_row=4))
    story.append(Spacer(1, 6))

    badge = severity_badge({"LOW": "low", "MEDIUM": "medium", "HIGH": "high", "CRITICAL": "critical"}[s.risk_level])
    risk_row = Table(
        [[Paragraph(f"<b>Overall Risk Score:</b> {s.risk_score}/100", STYLES["Body"]),
          Paragraph("<b>Risk Level:</b>", STYLES["Body"]), badge]],
        colWidths=[CONTENT_W * 0.5, CONTENT_W * 0.3, CONTENT_W * 0.2],
    )
    risk_row.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "MIDDLE")]))
    story.append(risk_row)
    story.append(Spacer(1, 10))
    story.append(Paragraph(s.narrative, STYLES["Body"]))
    return story


def _capture_info_content(report: Report):
    c = report.capture
    rows = [
        ("File Name", c.filename), ("File Size", c.file_size),
        ("Capture Start", c.start_time), ("Capture End", c.end_time),
        ("Duration", c.duration), ("Link Layer", c.link_layer),
        ("IPv4 Packets", f"{c.ipv4_packets:,}"), ("IPv6 Packets", f"{c.ipv6_packets:,}"),
        ("Average Packet Size", f"{c.avg_packet_size_bytes} bytes"),
        ("Average Bandwidth", f"{c.avg_bandwidth_mbps} Mbps"),
        ("Average Packets/sec", f"{c.avg_packets_per_sec}"),
        ("Total Bytes", c.total_bytes),
    ]
    story = [_section_heading(2, "Capture Information"), Spacer(1, 10)]
    story.append(styled_table(["Field", "Value"], rows, col_widths=[CONTENT_W * 0.45, CONTENT_W * 0.55]))
    return story


def _traffic_overview_content(report: Report):
    ts = report.traffic_statistics
    story = [_section_heading(3, "Traffic Overview"), Spacer(1, 10)]

    pie_data = [(p.protocol, p.packets) for p in ts.protocol_counts[:8]]
    pie = charts.pie_chart(pie_data, "Protocol Distribution", width=CONTENT_W * 0.48)
    bar = charts.bar_chart([(b, c) for b, c in ts.top_packet_sizes], "Packet Size Distribution",
                            ylabel="Packets", width=CONTENT_W * 0.48)
    row = Table([[pie, bar]], colWidths=[CONTENT_W * 0.5, CONTENT_W * 0.5])
    story.append(row)
    story.append(Spacer(1, 8))

    tl = report.timeline
    if tl.packets_per_bucket:
        pts = [(p.label, p.value) for p in tl.packets_per_bucket]
        story.append(charts.line_chart(pts, "Packets Over Time", "Packets", width=CONTENT_W))
        story.append(Spacer(1, 6))
    if tl.bandwidth_per_bucket:
        pts = [(p.label, p.value) for p in tl.bandwidth_per_bucket]
        story.append(charts.line_chart(pts, "Bandwidth Over Time", "Mbps", width=CONTENT_W, color="#00B4D8"))
        story.append(Spacer(1, 8))

    story.append(Paragraph("Protocol Breakdown", STYLES["SubHeading"]))
    story.append(styled_table(
        ["Protocol", "Packets", "%"],
        [(p.protocol, f"{p.packets:,}", f"{p.pct}%") for p in ts.protocol_counts],
        col_widths=[CONTENT_W * 0.4, CONTENT_W * 0.35, CONTENT_W * 0.25], align=[None, "right", "right"],
    ))
    return story


def _hosts_content(report: Report):
    story = [_section_heading(4, "Network Host Discovery"), Spacer(1, 10)]
    story.append(Paragraph(
        f"{len(report.hosts)} distinct host(s) were observed in this capture. "
        "MAC vendor lookup and hostname resolution are not yet implemented, so "
        "those columns show placeholders pending that feature.",
        STYLES["BodyMuted"],
    ))
    story.append(Spacer(1, 6))
    rows = [(h.ip, h.mac, f"{h.packets:,}", h.bytes, h.first_seen, h.last_seen, h.role)
            for h in report.hosts[:60]]
    story.append(styled_table(
        ["IP Address", "MAC Address", "Packets", "Bytes", "First Seen", "Last Seen", "Role"],
        rows,
        col_widths=[CONTENT_W * 0.16, CONTENT_W * 0.16, CONTENT_W * 0.10, CONTENT_W * 0.10,
                    CONTENT_W * 0.16, CONTENT_W * 0.16, CONTENT_W * 0.16],
        align=[None, None, "right", "right", None, None, None],
    ))
    return story


def _top_talkers_content(report: Report):
    tt = report.top_talkers
    story = [_section_heading(5, "Top Talkers"), Spacer(1, 10)]

    if tt.top_sources:
        chart = charts.bar_chart(
            [(t.ip, t.bandwidth_mbps) for t in tt.top_sources[:10]],
            "Top Talkers by Bandwidth (Mbps)", ylabel="Mbps", width=CONTENT_W, horizontal=True,
        )
        story.append(chart)
        story.append(Spacer(1, 8))

    story.append(Paragraph("Top Source IPs (Data Senders)", STYLES["SubHeading"]))
    story.append(styled_table(
        ["IP", "Packets", "Bytes", "%", "Bandwidth (Mbps)"],
        [(t.ip, f"{t.packets:,}", t.bytes, f"{t.pct}%", str(t.bandwidth_mbps)) for t in tt.top_sources],
        col_widths=[CONTENT_W * 0.28, CONTENT_W * 0.18, CONTENT_W * 0.18, CONTENT_W * 0.12, CONTENT_W * 0.24],
        align=[None, "right", "right", "right", "right"],
    ))
    story.append(Spacer(1, 8))
    story.append(Paragraph("Top Destination IPs (Data Receivers)", STYLES["SubHeading"]))
    story.append(styled_table(
        ["IP", "Packets", "Bytes", "%", "Bandwidth (Mbps)"],
        [(t.ip, f"{t.packets:,}", t.bytes, f"{t.pct}%", str(t.bandwidth_mbps)) for t in tt.top_destinations],
        col_widths=[CONTENT_W * 0.28, CONTENT_W * 0.18, CONTENT_W * 0.18, CONTENT_W * 0.12, CONTENT_W * 0.24],
        align=[None, "right", "right", "right", "right"],
    ))
    story.append(Spacer(1, 8))
    story.append(Paragraph("Top Conversations", STYLES["SubHeading"]))
    story.append(styled_table(
        ["Host A", "Host B", "Packets", "Bytes", "Duration"],
        [(c.a, c.b, f"{c.packets:,}", c.bytes, c.duration) for c in tt.top_conversations],
        col_widths=[CONTENT_W * 0.26, CONTENT_W * 0.26, CONTENT_W * 0.16, CONTENT_W * 0.16, CONTENT_W * 0.16],
        align=[None, None, "right", "right", "right"],
    ))
    return story


def _flows_content(report: Report):
    story = [_section_heading(6, "Flow Analysis"), Spacer(1, 10)]
    story.append(Paragraph("Top flows by total traffic volume, sorted descending.", STYLES["BodyMuted"]))
    story.append(Spacer(1, 6))
    rows = [(f.src_ip, f.dst_ip, f.src_port, f.dst_port, f.protocol, f"{f.packets:,}", f.bytes, f.duration, f.state)
            for f in report.flows]
    story.append(styled_table(
        ["Source IP", "Dest IP", "Src Port", "Dst Port", "Proto", "Packets", "Bytes", "Duration", "State"],
        rows,
        col_widths=[CONTENT_W * 0.16, CONTENT_W * 0.16, CONTENT_W * 0.08, CONTENT_W * 0.08,
                    CONTENT_W * 0.09, CONTENT_W * 0.11, CONTENT_W * 0.11, CONTENT_W * 0.10, CONTENT_W * 0.11],
        align=[None, None, "right", "right", "center", "right", "right", "right", "center"],
    ))
    return story


def _protocol_analysis_content(report: Report):
    p = report.protocols
    story = [_section_heading(7, "Protocol Analysis"), Spacer(1, 10)]

    story.append(Paragraph("TCP", STYLES["SubHeading"]))
    story.append(_pairs_table([
        ("Connections", p.tcp.connections), ("SYN Packets", p.tcp.syn), ("FIN Packets", p.tcp.fin),
        ("RST Packets", p.tcp.rst), ("Retransmissions (heuristic)", p.tcp.retransmissions),
        ("Failed Connections", p.tcp.failed_connections), ("Connection Resets", p.tcp.connection_resets),
    ]))
    story.append(Spacer(1, 8))

    story.append(Paragraph("UDP", STYLES["SubHeading"]))
    story.append(_pairs_table([
        ("UDP Streams", p.udp.streams), ("DHCP Packets", p.udp.dhcp),
        ("DNS Packets", p.udp.dns), ("NTP Packets", p.udp.ntp), ("Port 443/UDP (QUIC-candidate)", p.udp.quic),
    ]))
    if p.udp.top_ports:
        story.append(Spacer(1, 4))
        story.append(_pairs_table(p.udp.top_ports, headers=("Top UDP Port", "Packets")))
    story.append(Spacer(1, 8))

    story.append(Paragraph("DNS", STYLES["SubHeading"]))
    story.append(_pairs_table([
        ("Total Queries", p.dns.total_queries), ("Unique Domains", p.dns.unique_domains),
        ("Unique DNS Servers", p.dns.unique_dns_servers), ("NXDOMAIN Count", p.dns.nxdomain_count),
        ("Longest Domain", p.dns.longest_domain), ("Most Queried Domain", p.dns.most_queried_domain),
    ]))
    if p.dns.top_domains:
        story.append(Spacer(1, 4))
        story.append(_pairs_table(p.dns.top_domains, headers=("Top Domain", "Queries")))
    story.append(Spacer(1, 8))

    story.append(Paragraph("HTTP", STYLES["SubHeading"]))
    story.append(Paragraph(p.http.note, STYLES["BodyMuted"]))
    if p.http.hosts:
        story.append(Spacer(1, 4))
        story.append(_pairs_table(p.http.hosts, headers=("Host (port 80)", "Packets")))
    story.append(Spacer(1, 8))

    story.append(Paragraph("HTTPS", STYLES["SubHeading"]))
    story.append(Paragraph(p.https.note, STYLES["BodyMuted"]))
    if p.https.most_contacted_hosts:
        story.append(Spacer(1, 4))
        story.append(_pairs_table(p.https.most_contacted_hosts, headers=("Host (port 443)", "Packets")))
    story.append(Spacer(1, 8))

    story.append(Paragraph("ICMP", STYLES["SubHeading"]))
    story.append(Paragraph(p.icmp.note, STYLES["BodyMuted"]))
    story.append(Spacer(1, 4))
    story.append(_pairs_table([("Total ICMP Packets", p.icmp.total)]))
    story.append(Spacer(1, 8))

    story.append(Paragraph("ARP", STYLES["SubHeading"]))
    story.append(_pairs_table([
        ("Requests", p.arp.requests), ("Replies", p.arp.replies),
        ("Duplicate ARP", p.arp.duplicate_arp),
        ("Potential Spoofing Incidents", p.arp.potential_spoofing_incidents),
    ]))
    return story


def _ports_content(report: Report):
    pa = report.ports
    story = [_section_heading(8, "Port Analysis"), Spacer(1, 10)]
    if pa.top_ports:
        chart = charts.bar_chart(
            [(f"{r.port}", r.packets) for r in pa.top_ports[:10]],
            "Top Destination Ports", ylabel="Packets", width=CONTENT_W,
        )
        story.append(chart)
        story.append(Spacer(1, 8))

    story.append(Paragraph("Top Ports / Services", STYLES["SubHeading"]))
    story.append(styled_table(
        ["Port", "Service", "Packets", "%"],
        [(r.port, r.service, f"{r.packets:,}", f"{r.pct}%") for r in pa.top_ports],
        col_widths=[CONTENT_W * 0.15, CONTENT_W * 0.35, CONTENT_W * 0.25, CONTENT_W * 0.25],
        align=["center", None, "right", "right"],
    ))
    story.append(Spacer(1, 8))
    story.append(Paragraph("Unexpected / Rare Ports (&gt;1024, unrecognized service)", STYLES["SubHeading"]))
    story.append(styled_table(
        ["Port", "Service", "Packets", "%"],
        [(r.port, r.service, f"{r.packets:,}", f"{r.pct}%") for r in pa.unexpected_ports],
        col_widths=[CONTENT_W * 0.15, CONTENT_W * 0.35, CONTENT_W * 0.25, CONTENT_W * 0.25],
        align=["center", None, "right", "right"],
    ))
    return story


def _dns_intel_content(report: Report):
    d = report.dns_intelligence
    story = [_section_heading(9, "DNS Intelligence"), Spacer(1, 10)]

    if d.top_domains:
        chart = charts.bar_chart(d.top_domains[:10], "Top Queried Domains", ylabel="Queries", width=CONTENT_W)
        story.append(chart)
        story.append(Spacer(1, 8))

    story.append(Paragraph("Top DNS Servers", STYLES["SubHeading"]))
    story.append(_pairs_table(d.top_dns_servers, headers=("DNS Server", "Responses")))
    story.append(Spacer(1, 8))

    story.append(Paragraph("High-Frequency Domains", STYLES["SubHeading"]))
    story.append(Paragraph(
        "Domains queried unusually often relative to normal traffic — can indicate "
        "beaconing, telemetry, or automated polling.", STYLES["BodyMuted"]))
    story.append(Spacer(1, 4))
    story.append(_pairs_table(d.high_frequency_domains, headers=("Domain", "Queries")))
    story.append(Spacer(1, 8))

    story.append(Paragraph("Very Long / Suspicious Domain Labels", STYLES["SubHeading"]))
    if d.very_long_domains:
        rows = [(dom, "") for dom in d.very_long_domains]
        story.append(styled_table(["Domain", ""], rows, col_widths=[CONTENT_W * 0.9, CONTENT_W * 0.1]))
    else:
        story.append(Paragraph("No unusually long domain labels were observed.", STYLES["Body"]))
    story.append(Spacer(1, 8))

    story.append(Paragraph("DNS Tunneling Indicators", STYLES["SubHeading"]))
    for line in d.tunneling_indicators:
        story.append(Paragraph(f"&bull; {line}", STYLES["Body"]))
        story.append(Spacer(1, 3))
    return story


def _timeline_content(report: Report):
    tl = report.timeline
    story = [_section_heading(10, "Timeline Analysis"), Spacer(1, 10)]
    if tl.alerts_over_time:
        chart = charts.bar_chart(
            [(p.label, p.value) for p in tl.alerts_over_time], "Alerts Over Time",
            ylabel="Alerts", width=CONTENT_W,
        )
        story.append(chart)
    else:
        story.append(Paragraph("No security alerts were generated during this capture.", STYLES["Body"]))
    return story


def _security_findings_content(report: Report):
    story = [_section_heading(11, "Security Findings"), Spacer(1, 10)]
    if not report.security_findings:
        story.append(Paragraph(
            "PacketRadar did not identify any security findings in this capture.", STYLES["Body"]))
        return story

    for f in report.security_findings:
        badge = severity_badge(f.severity)
        header = Table(
            [[badge, Paragraph(f"<b>{f.category}</b>", STYLES["Body"]),
              Paragraph(f"Confidence: {f.confidence}", STYLES["BodyMuted"])]],
            colWidths=[24 * mm, CONTENT_W - 24 * mm - 35 * mm, 35 * mm],
        )
        header.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "MIDDLE")]))

        body_rows = [
            ["Affected Host", f.affected_host or "-"],
            ["Evidence", f.evidence],
            ["Recommendation", f.recommendation],
        ]
        body = styled_table(["Field", "Detail"], body_rows,
                             col_widths=[CONTENT_W * 0.2, CONTENT_W * 0.8])

        block = KeepTogether([header, Spacer(1, 4), body, Spacer(1, 10)])
        story.append(block)
    return story


def _alerts_summary_content(report: Report):
    a = report.alerts_summary
    story = [_section_heading(12, "Alerts Summary"), Spacer(1, 10)]
    counts = {"critical": a.critical, "high": a.high, "medium": a.medium,
              "low": a.low, "informational": a.informational}
    chart = charts.severity_distribution_chart(counts, width=CONTENT_W * 0.6)
    story.append(chart)
    story.append(Spacer(1, 8))
    story.append(styled_table(
        ["Severity", "Count"],
        [("Critical", a.critical), ("High", a.high), ("Medium", a.medium),
         ("Low", a.low), ("Informational", a.informational), ("Total", a.total)],
        col_widths=[CONTENT_W * 0.7, CONTENT_W * 0.3], align=[None, "right"],
    ))
    return story


def _recommendations_content(report: Report):
    story = [_section_heading(13, "Recommendations"), Spacer(1, 10)]
    for r in report.recommendations:
        badge = severity_badge(r.priority)
        row = Table([[badge, Paragraph(r.text, STYLES["Body"])]],
                     colWidths=[24 * mm, CONTENT_W - 24 * mm])
        row.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "TOP"),
                                  ("TOPPADDING", (0, 0), (-1, -1), 4),
                                  ("BOTTOMPADDING", (0, 0), (-1, -1), 8)]))
        story.append(row)
    return story


def _appendix_content(report: Report):
    ap = report.appendix
    story = [_section_heading(14, "Appendix"), Spacer(1, 10)]

    story.append(Paragraph("Top IPs", STYLES["SubHeading"]))
    story.append(_pairs_table(ap.top_ips, headers=("IP", "Packets")))
    story.append(Spacer(1, 8))

    story.append(Paragraph("Top Domains", STYLES["SubHeading"]))
    story.append(_pairs_table(ap.top_domains, headers=("Domain", "Queries")))
    story.append(Spacer(1, 8))

    story.append(Paragraph("Protocol Counts", STYLES["SubHeading"]))
    story.append(styled_table(
        ["Protocol", "Packets", "%"],
        [(p.protocol, f"{p.packets:,}", f"{p.pct}%") for p in ap.protocol_counts],
        col_widths=[CONTENT_W * 0.4, CONTENT_W * 0.35, CONTENT_W * 0.25], align=[None, "right", "right"],
    ))
    story.append(Spacer(1, 8))

    story.append(Paragraph("Packet Size Distribution", STYLES["SubHeading"]))
    story.append(_pairs_table(ap.packet_size_distribution, headers=("Size Range", "Packets")))
    story.append(Spacer(1, 8))

    story.append(Paragraph("Glossary", STYLES["SubHeading"]))
    story.append(styled_table(
        ["Term", "Definition"], ap.glossary,
        col_widths=[CONTENT_W * 0.22, CONTENT_W * 0.78],
    ))
    return story


# ---------------------------------------------------------------------------
# Top-level entry point
# ---------------------------------------------------------------------------


def generate_pdf(report: Report) -> bytes:
    """Renders the full `Report` object to PDF bytes."""
    buf = io.BytesIO()
    doc = BaseDocTemplate(buf, pagesize=PAGE_SIZE,
                           leftMargin=MARGIN, rightMargin=MARGIN,
                           topMargin=MARGIN, bottomMargin=MARGIN,
                           title="PacketRadar PCAP Analysis Report")

    cover_frame = Frame(0, 0, PAGE_W, PAGE_H, id="cover", leftPadding=24 * mm,
                         rightPadding=24 * mm, topPadding=0, bottomPadding=20 * mm)
    body_frame = Frame(MARGIN, MARGIN, CONTENT_W, PAGE_H - 2 * MARGIN - 6 * mm,
                        id="body")

    doc.addPageTemplates([
        PageTemplate(id="Cover", frames=[cover_frame], onPage=_make_onpage("cover")),
        PageTemplate(id="Body", frames=[body_frame], onPage=_make_onpage("body")),
    ])

    story = []
    story.extend(_cover_content(report))
    story.append(NextPageTemplate("Body"))
    story.append(PageBreak())

    story.extend(_toc_content())
    story.append(PageBreak())

    for builder in (
        _executive_summary_content, _capture_info_content, _traffic_overview_content,
        _hosts_content, _top_talkers_content, _flows_content, _protocol_analysis_content,
        _ports_content, _dns_intel_content, _timeline_content, _security_findings_content,
        _alerts_summary_content, _recommendations_content, _appendix_content,
    ):
        story.extend(builder(report))
        story.append(PageBreak())

    # Drop the trailing page break at the very end.
    if story and isinstance(story[-1], PageBreak):
        story.pop()

    doc.build(story)
    return buf.getvalue()
