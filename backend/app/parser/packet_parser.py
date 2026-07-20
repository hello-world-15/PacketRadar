from datetime import datetime
from typing import Optional

from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import ARP, Ether
from scapy.packet import Raw

from app.models.packet import PacketModel

# Common DNS QTYPE values we bother naming — anything else falls back to
# its raw numeric value. Not exhaustive (there are ~60 registered types),
# just the ones that actually show up in normal traffic.
DNS_QTYPES = {
    1: "A",
    2: "NS",
    5: "CNAME",
    6: "SOA",
    12: "PTR",
    15: "MX",
    16: "TXT",
    28: "AAAA",
    33: "SRV",
    255: "ANY",
}

MAX_DNS_ANSWERS = 5

DNS_RCODES = {
    0: "NOERROR",
    1: "FORMERR",
    2: "SERVFAIL",
    3: "NXDOMAIN",
    4: "NOTIMP",
    5: "REFUSED",
}


class PacketParser:
    """
    Converts a Scapy packet into PacketRadar's internal PacketModel.
    """

    @staticmethod
    def _parse_dns(packet) -> tuple[Optional[str], Optional[str]]:
        """Pulls the queried domain and (if present) resolved answers out
        of a DNS packet's question/answer sections.

        Returns (query, answer) where `query` is the domain name asked
        about (present on both queries and responses — a response
        echoes the question it's answering) and `answer` is a
        comma-joined string of resolved values (IPs for A/AAAA, hostnames
        for CNAME/PTR/NS/MX, etc.), or None if there's nothing to report
        (e.g. NXDOMAIN, or this is the query half with no answer yet).
        """
        query: Optional[str] = None
        answer: Optional[str] = None

        if not packet.haslayer(DNS):
            return query, answer

        dns_layer = packet[DNS]

        if dns_layer.qdcount and packet.haslayer(DNSQR):
            qname = packet[DNSQR].qname
            if isinstance(qname, bytes):
                qname = qname.decode(errors="ignore")
            qtype_name = DNS_QTYPES.get(packet[DNSQR].qtype, str(packet[DNSQR].qtype))
            query = f"{qname.rstrip('.')} ({qtype_name})"

        if dns_layer.ancount:
            values: list[str] = []
            # Scapy exposes multiple answer records as a list-like field
            # on dns_layer.an (not chained via .payload the way stacked
            # protocol layers usually are) — iterate it directly rather
            # than walking a payload chain.
            answers = dns_layer.an
            if answers is not None and not isinstance(answers, list):
                answers = [answers]
            for rr in answers or []:
                if not isinstance(rr, DNSRR) or len(values) >= MAX_DNS_ANSWERS:
                    break
                rdata = rr.rdata
                if isinstance(rdata, bytes):
                    rdata = rdata.decode(errors="ignore").rstrip(".")
                values.append(str(rdata))
            if values:
                answer = ", ".join(values)

        return query, answer

    @staticmethod
    def _dns_rcode_name(packet) -> str:
        """Human-readable response code for a DNS response with no
        answer records (NXDOMAIN, SERVFAIL, etc.) — falls back to the
        raw numeric code for anything not in DNS_RCODES."""
        if not packet.haslayer(DNS):
            return "UNKNOWN"
        rcode = packet[DNS].rcode
        # Scapy may hand this back as an int or an already-resolved enum
        # string depending on version — normalize to an int for the lookup.
        try:
            rcode = int(rcode)
        except (TypeError, ValueError):
            return str(rcode).upper()
        return DNS_RCODES.get(rcode, f"RCODE {rcode}")

    @staticmethod
    def parse(packet, interface: str = "Unknown", timestamp: Optional[datetime] = None) -> Optional[PacketModel]:
        try:

            src_ip = "Unknown"
            dst_ip = "Unknown"

            src_port = None
            dst_port = None

            protocol = "OTHER"
            info = ""
            dns_query: Optional[str] = None
            dns_answer: Optional[str] = None
            dns_rcode: Optional[str] = None

            # -----------------------------
            # MAC Address
            # -----------------------------
            # Populated from the Ethernet layer where present. ARP's own
            # hwsrc is preferred over the outer Ethernet source once we
            # know it's an ARP packet — that's the field ARP Spoofing
            # Detection actually cares about (who is *claiming* this IP),
            # and it's the semantically correct source even though in
            # practice it matches the Ethernet header on a normal frame.

            src_mac: Optional[str] = None
            dst_mac: Optional[str] = None

            if packet.haslayer(Ether):
                src_mac = packet[Ether].src
                dst_mac = packet[Ether].dst

            # -----------------------------
            # IP Address
            # -----------------------------

            if packet.haslayer(IP):
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst

            elif packet.haslayer(IPv6):
                src_ip = packet[IPv6].src
                dst_ip = packet[IPv6].dst

            elif packet.haslayer(ARP):
                src_ip = packet[ARP].psrc
                dst_ip = packet[ARP].pdst
                src_mac = packet[ARP].hwsrc or src_mac
                protocol = "ARP"
                is_request = packet[ARP].op == 1
                info = (
                    f"Who has {dst_ip}? Tell {src_ip}" if is_request else f"{src_ip} is at {packet[ARP].hwsrc}"
                )

            # -----------------------------
            # Protocol
            # -----------------------------

            if packet.haslayer(TCP):
                protocol = "TCP"

                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport

                flags = packet[TCP].sprintf("%TCP.flags%")
                info = f"TCP {src_port} \u2192 {dst_port} [{flags}]"

            elif packet.haslayer(UDP):
                src_port = packet[UDP].sport
                dst_port = packet[UDP].dport

                # DNS is UDP on port 53 in either direction, not a
                # separate transport layer — Scapy has a DNS layer too,
                # so once we know we're looking at port 53 we go parse
                # it for the actual query/answer content rather than
                # just labeling the port.
                if src_port == 53 or dst_port == 53:
                    protocol = "DNS"
                    is_query_direction = dst_port == 53
                    dns_query, dns_answer = PacketParser._parse_dns(packet)

                    if not is_query_direction:
                        # Response direction — always record the rcode,
                        # success ("NOERROR") or failure (NXDOMAIN/
                        # SERVFAIL/etc.), independently of whether a
                        # question was extracted. Single source of truth
                        # for "did this response actually resolve" — see
                        # docs/contracts/pcap-dns-analysis.md.
                        dns_rcode = "NOERROR" if dns_answer else PacketParser._dns_rcode_name(packet)

                    if dns_answer:
                        info = f"DNS response: {dns_query or '?'} \u2192 {dns_answer}"
                    elif dns_query and is_query_direction:
                        info = f"DNS query: {dns_query}"
                    elif dns_query and not is_query_direction:
                        # A response with a question but no answer record
                        # (NXDOMAIN, SERVFAIL, etc.) — surface the actual
                        # response code instead of just calling it a query.
                        info = f"DNS response: {dns_query} \u2192 {dns_rcode}"
                    else:
                        # DNS on the wire but we couldn't pull a question
                        # out of it (malformed/truncated) — don't crash,
                        # just fall back to a generic direction label.
                        info = "DNS query" if is_query_direction else "DNS response"
                else:
                    protocol = "UDP"
                    info = "UDP"

            elif packet.haslayer(ICMP):
                protocol = "ICMP"

                info = "ICMP"

            # -----------------------------
            # Payload
            # -----------------------------

            payload_size = 0

            if packet.haslayer(Raw):
                payload_size = len(packet[Raw].load)

            # -----------------------------
            # Flow Key
            # -----------------------------

            flow_key = (
                f"{src_ip}:{src_port}-"
                f"{dst_ip}:{dst_port}-"
                f"{protocol}"
            )

            # -----------------------------
            # PacketModel
            # -----------------------------

            return PacketModel(
                timestamp=timestamp if timestamp is not None else datetime.now(),
                interface=interface,
                direction="UNKNOWN",
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                protocol=protocol,
                length=len(packet),
                payload_size=payload_size,
                flow_key=flow_key,
                info=info,
                dns_query=dns_query,
                dns_answer=dns_answer,
                dns_rcode=dns_rcode,
                src_mac=src_mac,
                dst_mac=dst_mac,
            )

        except Exception as e:
            print(f"[PacketParser] {e}")
            return None