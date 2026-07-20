"""
Pydantic models for the "stats" widget group.

These field names and types are a direct implementation of
docs/contracts/stats.md — do not rename fields here without updating
that document (and the frontend types that mirror it).
"""

from pydantic import BaseModel, Field


class ProtocolCount(BaseModel):
    """One slice of the protocol distribution pie. Raw cumulative count —
    the frontend computes percentages itself so this field never needs to
    change shape if we add a new protocol label later."""

    label: str
    value: int = Field(..., ge=0)


class LiveStats(BaseModel):
    """Snapshot of live capture statistics, emitted once per second."""

    packets_per_sec: int = Field(..., ge=0)
    bandwidth_mbps: float = Field(..., ge=0)
    upload_mbps: float = Field(
        0.0,
        ge=0,
        description=(
            "Bytes in the same rolling 1s window as bandwidth_mbps, restricted to "
            "packets whose source IP matched a local IP at capture start. 0.0 if "
            "local IP resolution failed — see docs/contracts/stats.md."
        ),
    )
    download_mbps: float = Field(
        0.0,
        ge=0,
        description=(
            "Same window, restricted to packets whose destination IP matched a "
            "local IP. Packets matching neither upload nor download (LAN-to-LAN "
            "traffic between two other hosts) still count in bandwidth_mbps but "
            "not here — see docs/contracts/stats.md."
        ),
    )
    active_connections: int = Field(..., ge=0)
    threat_alert_count: int = Field(
        0, ge=0, description="Stubbed at 0 until the Threat Detection Engine exists."
    )
    lan_device_count: int = Field(
        0, ge=0, description="Stubbed at 0 until the Host Discovery module exists."
    )
    dropped_packets: int = Field(..., ge=0)
    protocol_distribution: list[ProtocolCount] = Field(
        default_factory=list,
        description=(
            "Cumulative packet counts per protocol label since the capture "
            "started (not windowed like packets_per_sec — see Statistics "
            "Engine docstring). Labels match the frontend's Protocol union: "
            "TCP | UDP | ICMP | DNS | ARP | Other."
        ),
    )


class StatsUpdateEvent(BaseModel):
    """Envelope sent over the WebSocket, matches the `type` + `data` shape
    documented in stats.md so the frontend can dispatch on `type` if more
    event types share the same socket later."""

    type: str = "stats:update"
    data: LiveStats
