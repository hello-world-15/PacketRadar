"""
Pydantic models for the "packets" widget group. Field names/types are a
direct implementation of docs/contracts/packets.md.

Deliberately a slimmer shape than app.models.PacketModel — that's the
rich internal representation the parser produces; this is only the
subset the Live Packet Stream table actually renders, same relationship
schemas/hosts.py has to a fuller internal host record.
"""

from __future__ import annotations

from typing import Optional

from pydantic import BaseModel, Field


class PacketStreamRow(BaseModel):
    no: int = Field(..., description="Sequence number assigned by PacketStreamEngine, not a wire value")
    time: float = Field(..., description="Unix timestamp (seconds) when the packet was parsed")
    source: str
    destination: str
    protocol: str
    length: int = Field(..., ge=0)
    process: Optional[str] = Field(
        None, description="Not resolved in v1 — see docs/contracts/packets.md"
    )
    info: str = ""
    dns_query: Optional[str] = Field(
        None, description="Domain + record type asked about, e.g. 'example.com (A)' — only set when protocol is DNS"
    )
    dns_answer: Optional[str] = Field(
        None, description="Comma-joined resolved values (IPs, CNAMEs, etc.) — only set on DNS responses that resolved something"
    )


class PacketsUpdateEvent(BaseModel):
    """Envelope sent over the WebSocket, matches the `type` + `data`
    shape used by stats:update and hosts:update on the same socket."""

    type: str = "packets:update"
    data: list[PacketStreamRow]
