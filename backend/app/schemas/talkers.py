"""
Pydantic models for the "Top Talkers" widget group. Field names/types
are a direct implementation of docs/contracts/talkers.md.
"""

from __future__ import annotations

from typing import Optional

from pydantic import BaseModel, Field


class TopTalker(BaseModel):
    ip: str
    hostname: Optional[str] = Field(
        None,
        description=(
            "Borrowed from HostDiscoveryEngine's own reverse-DNS "
            "results (same resolver, same cache) when this IP matches "
            "a known host's current IP — see docs/contracts/hosts.md "
            "and docs/contracts/talkers.md. Null if unresolved or if "
            "this IP hasn't been seen via ARP (off-subnet traffic)."
        ),
    )
    packets: int = Field(..., ge=0, description="Cumulative count for the capture session")
    bandwidth_mbps: float = Field(..., ge=0, description="Smoothed over a 5s rolling window")
    bandwidth_pct: float = Field(
        0, ge=0, le=100, description="Relative to the top talker in this snapshot"
    )
    connections: int = Field(..., ge=0, description="Distinct active flows touching this IP")


class TalkersUpdateEvent(BaseModel):
    type: str = "talkers:update"
    data: list[TopTalker]
