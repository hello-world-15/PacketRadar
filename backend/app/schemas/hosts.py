"""
Pydantic models for the "hosts" widget group. Field names/types are a
direct implementation of docs/contracts/hosts.md.
"""

from typing import Literal, Optional

from pydantic import BaseModel, Field


class DiscoveredHost(BaseModel):
    ip: str
    mac: str
    hostname: Optional[str] = Field(
        None,
        description=(
            "Reverse-DNS name, filled in asynchronously by "
            "app.capture.hostname_resolver — see docs/contracts/hosts.md. "
            "Stays null for hosts with no PTR record, which is a normal "
            "outcome for plenty of consumer/IoT devices, not a failure."
        ),
    )
    last_seen: float = Field(..., description="Unix timestamp (seconds)")
    status: Literal["online", "offline"]


class HostsUpdateEvent(BaseModel):
    type: str = "hosts:update"
    data: list[DiscoveredHost]
