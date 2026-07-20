"""
Minimal WebSocket connection registry. Deliberately not a pub/sub system —
we only have one broadcast channel today (stats). If a second event type
is added on the same socket (packet stream, threat alerts), extend
`broadcast` to take a channel name rather than building a message bus
prematurely.
"""

from __future__ import annotations

from fastapi import WebSocket


class ConnectionManager:
    def __init__(self) -> None:
        self._connections: set[WebSocket] = set()

    async def connect(self, websocket: WebSocket) -> None:
        await websocket.accept()
        self._connections.add(websocket)

    def disconnect(self, websocket: WebSocket) -> None:
        self._connections.discard(websocket)

    @property
    def active_count(self) -> int:
        return len(self._connections)

    async def broadcast_json(self, payload: dict) -> None:
        dead: list[WebSocket] = []
        for connection in self._connections:
            try:
                await connection.send_json(payload)
            except Exception:
                dead.append(connection)
        for connection in dead:
            self.disconnect(connection)
