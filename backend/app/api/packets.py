from fastapi import APIRouter

from app.cache import packet_cache

router = APIRouter(prefix="/packets", tags=["Packets"])


@router.get("/")
def get_packets(limit: int = 100):
    packets = packet_cache.latest(limit)

    return [packet.model_dump() for packet in packets]