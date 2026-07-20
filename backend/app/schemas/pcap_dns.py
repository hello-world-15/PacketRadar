"""
Pydantic models for GET /api/pcap/{capture_id}/dns — see
docs/contracts/pcap-dns-analysis.md.

Deliberately separate from app.schemas.pcap's DnsAnalysis/DomainCount
(which back the older, unwired app.engines.pcap_insights module) rather
than reusing them: this endpoint's `top_domains` rows use `queries` as
the count field name, not `count`, to match `src/data/mockData.ts`'s
existing shape exactly. Two classes named `DnsAnalysis` with
incompatibly-shaped `top_domains` rows would be a confusing collision;
naming these distinctly avoids it.
"""

from __future__ import annotations

from pydantic import BaseModel


class TopDomainRow(BaseModel):
    domain: str
    queries: int


class DomainCountRow(BaseModel):
    domain: str
    count: int


class DnsAnalysisResponse(BaseModel):
    top_domains: list[TopDomainRow]
    repeated_queries: list[DomainCountRow]
    failed_queries: list[DomainCountRow]
