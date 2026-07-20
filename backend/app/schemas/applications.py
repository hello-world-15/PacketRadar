"""
Pydantic models for the "Top Applications" widget. Field names/types are
a direct implementation of docs/contracts/applications.md.

No `icon` field here on purpose — which emoji represents "chrome.exe" is
a presentation concern the frontend already owns (see
src/data/mockData.ts's `appIcons` map, reused for real data too), the
same way `bandwidth_pct` in talkers.py is computed server-side but
`icon` here isn't: whether a value needs the backend's authority (byte
counts, PIDs) or is pure UI decoration determines which side computes it.
"""

from __future__ import annotations

from pydantic import BaseModel, Field


class TopApplication(BaseModel):
    pid: int = Field(..., description="OS process id at the time of the most recent packet credited to it")
    name: str = Field(..., description="Process name as reported by the OS, e.g. 'chrome.exe' on Windows")
    upload_kbps: float = Field(..., ge=0, description="Smoothed over a 5s rolling window, same as talkers.py")
    download_kbps: float = Field(..., ge=0, description="Smoothed over a 5s rolling window, same as talkers.py")
    connections: int = Field(..., ge=0, description="Distinct active flows attributed to this pid")


class ApplicationsUpdateEvent(BaseModel):
    type: str = "applications:update"
    data: list[TopApplication]
