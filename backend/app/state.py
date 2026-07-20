"""
Process-wide singletons.

Both `app.ws.live_socket` (broadcasts live data) and `app.api.capture`
(start/stop/export REST endpoints) need to act on the *same*
StatisticsEngine / HostDiscoveryEngine / PacketStreamEngine /
TopTalkersEngine / ThreatDetectionEngine / TopApplicationsEngine /
PacketCapture instances. Previously these were only created inside live_socket.py; that
worked while the only way to control capture was implicitly (start on
first WS connect, stop on last disconnect), but the explicit Start/Stop
Capture button needs to reach the same `capture` object from a plain
REST router. Pulling the construction out to its own module avoids a
circular import between app.api.capture and app.ws.live_socket.
"""

from __future__ import annotations

from app.capture.active_scan import ActiveScanner
from app.capture.hostname_resolver import HostnameResolver
from app.capture.process_resolution import ProcessResolver
from app.capture.sniffer import PacketCapture
from app.engines.host_discovery import HostDiscoveryEngine
from app.engines.packet_stream import PacketStreamEngine
from app.engines.statistics import StatisticsEngine
from app.engines.threat_detection import ThreatDetectionEngine
from app.engines.top_applications import TopApplicationsEngine
from app.engines.top_talkers import TopTalkersEngine
from app.ws.manager import ConnectionManager

stats_engine = StatisticsEngine()
host_engine = HostDiscoveryEngine()
packet_engine = PacketStreamEngine()
talkers_engine = TopTalkersEngine()
threat_engine = ThreatDetectionEngine()
apps_engine = TopApplicationsEngine()
process_resolver = ProcessResolver()
manager = ConnectionManager()

# Reverse-DNS lookups feed host_engine's hostname field; the active ARP
# sweep feeds host_engine's ip/mac table directly and also triggers a
# hostname lookup for anything it finds (via on_sighting), same as
# passive ARP sightings do from inside PacketCapture._on_packet. See
# app.capture.hostname_resolver / app.capture.active_scan.
hostname_resolver = HostnameResolver(host_engine)
active_scanner = ActiveScanner(host_engine, on_sighting=hostname_resolver.request)

capture = PacketCapture(
    stats_engine,
    host_engine,
    packet_engine,
    talkers_engine,
    threat_engine,
    apps_engine,
    process_resolver,
    hostname_resolver,
    active_scanner,
)
