"""
Pydantic models for PCAP Analyzer Protocol Distribution. Field names are
a direct implementation of docs/contracts/pcap-protocol-distribution.md.

`ProtocolCount` itself is reused from app.schemas.stats (the live
version's identical {label, value} shape) rather than redefined here —
see the contract's "Schema reuse, not duplication".
"""

from __future__ import annotations

from pydantic import BaseModel

from app.schemas.stats import ProtocolCount


class ProtocolDistributionResponse(BaseModel):
    protocol_distribution: list[ProtocolCount]
