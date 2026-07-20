"""
Pydantic models for live threat alerts (Module 7).

Named `threats_live` rather than `threats` to leave room for a distinct
PCAP-analyzer threats schema later — `src/pages/PcapAnalyzer.tsx` already
has its own unrelated `analyzerThreats` mock data for static file
analysis, which is a different feature with a different (offline,
per-upload) data shape from this one (live, streaming). No such schema
exists yet, but the name is chosen defensively so the two don't collide
if/when it does.

Field names/types are a direct implementation of docs/contracts/threats.md.
"""

from __future__ import annotations

from pydantic import BaseModel, Field


class ThreatAlertRow(BaseModel):
    no: int = Field(
        ..., description="Sequence number assigned by ThreatDetectionEngine, engine-internal only"
    )
    id: str = Field(..., description="Stable unique id, f'threat-{no}' — doubles as the frontend's merge key")
    time: float = Field(..., description="Unix timestamp (seconds) when the alert was raised")
    severity: str = Field(..., description="'high' or 'medium' — see docs/contracts/threats.md")
    threat: str
    source: str
    description: str


class ThreatsUpdateEvent(BaseModel):
    """Envelope sent over the WebSocket, matches the `type` + `data`
    shape used by every other event on the same socket."""

    type: str = "threats:update"
    data: list[ThreatAlertRow]
