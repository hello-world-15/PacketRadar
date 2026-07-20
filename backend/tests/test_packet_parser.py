"""
Unit tests for PacketParser — specifically the DNS extraction added on
top of the original TCP/UDP/ICMP/ARP labeling.

These build synthetic packets with Scapy and round-trip them through
`bytes(...)` before parsing. That round-trip matters: Scapy only
computes fields like `qdcount`/`ancount` (and decides whether multiple
answer records survive as real DNSRR layers vs. get left as unparsed
Raw bytes) at *build* time, the same way a real capture hands the
sniffer already-serialized wire bytes. Parsing a packet object you just
constructed in memory, without going through bytes(), will silently see
qdcount/ancount as None and doesn't exercise the real code path. No root
or live capture needed either way — these are pure in-memory packets.
"""

from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import IP, UDP

from app.parser.packet_parser import PacketParser


def _wire(pkt):
    """Round-trip a packet through its wire bytes, like a real capture."""
    return IP(bytes(pkt))


def test_dns_query_extracts_domain_and_type():
    pkt = _wire(
        IP(src="192.168.1.10", dst="8.8.8.8")
        / UDP(sport=51000, dport=53)
        / DNS(rd=1, qd=DNSQR(qname="example.com", qtype="A"))
    )
    model = PacketParser.parse(pkt)
    assert model.protocol == "DNS"
    assert model.dns_query == "example.com (A)"
    assert model.dns_answer is None
    assert model.info == "DNS query: example.com (A)"


def test_dns_response_extracts_single_answer():
    pkt = _wire(
        IP(src="8.8.8.8", dst="192.168.1.10")
        / UDP(sport=53, dport=51000)
        / DNS(
            qr=1,
            qd=DNSQR(qname="example.com", qtype="A"),
            ancount=1,
            an=DNSRR(rrname="example.com", type="A", rdata="93.184.216.34", ttl=300),
        )
    )
    model = PacketParser.parse(pkt)
    assert model.protocol == "DNS"
    assert model.dns_query == "example.com (A)"
    assert model.dns_answer == "93.184.216.34"
    assert "93.184.216.34" in model.info


def test_dns_response_extracts_multiple_answers():
    pkt = _wire(
        IP(src="8.8.8.8", dst="192.168.1.10")
        / UDP(sport=53, dport=51000)
        / DNS(
            qr=1,
            qd=DNSQR(qname="example.com", qtype="A"),
            ancount=2,
            an=DNSRR(rrname="example.com", type="A", rdata="93.184.216.34", ttl=300)
            / DNSRR(rrname="example.com", type="A", rdata="93.184.216.35", ttl=300),
        )
    )
    model = PacketParser.parse(pkt)
    assert model.dns_answer == "93.184.216.34, 93.184.216.35"


def test_dns_cname_response_reports_hostname_answer():
    pkt = _wire(
        IP(src="8.8.8.8", dst="192.168.1.10")
        / UDP(sport=53, dport=51000)
        / DNS(
            qr=1,
            qd=DNSQR(qname="www.example.com", qtype="A"),
            ancount=1,
            an=DNSRR(rrname="www.example.com", type="CNAME", rdata="example.com", ttl=300),
        )
    )
    model = PacketParser.parse(pkt)
    assert model.dns_query == "www.example.com (A)"
    assert model.dns_answer == "example.com"


def test_dns_aaaa_query_names_the_record_type():
    pkt = _wire(
        IP(src="192.168.1.10", dst="8.8.8.8")
        / UDP(sport=51000, dport=53)
        / DNS(rd=1, qd=DNSQR(qname="ipv6.example.com", qtype="AAAA"))
    )
    model = PacketParser.parse(pkt)
    assert model.dns_query == "ipv6.example.com (AAAA)"


def test_dns_nxdomain_response_has_no_answer_but_names_the_rcode():
    pkt = _wire(
        IP(src="8.8.8.8", dst="192.168.1.10")
        / UDP(sport=53, dport=51000)
        / DNS(qr=1, rcode=3, qd=DNSQR(qname="doesnotexist.example.com", qtype="A"), ancount=0)
    )
    model = PacketParser.parse(pkt)
    assert model.dns_answer is None
    assert "NXDOMAIN" in model.info
    # Must not be mislabeled as a query just because it has no answer.
    assert model.info.startswith("DNS response")


def test_dns_servfail_response_names_the_rcode():
    pkt = _wire(
        IP(src="8.8.8.8", dst="192.168.1.10")
        / UDP(sport=53, dport=51000)
        / DNS(qr=1, rcode=2, qd=DNSQR(qname="timeout.example.com", qtype="A"), ancount=0)
    )
    model = PacketParser.parse(pkt)
    assert "SERVFAIL" in model.info


def test_non_dns_udp_is_unaffected():
    pkt = _wire(IP(src="192.168.1.10", dst="10.0.0.5") / UDP(sport=51820, dport=51820))
    model = PacketParser.parse(pkt)
    assert model.protocol == "UDP"
    assert model.dns_query is None
    assert model.dns_answer is None


def test_tcp_still_reports_ports_and_flags():
    from scapy.layers.inet import TCP

    pkt = _wire(IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=51372, dport=443, flags="PA"))
    model = PacketParser.parse(pkt)
    assert model.protocol == "TCP"
    assert "51372" in model.info and "443" in model.info


def test_arp_request_has_descriptive_info():
    from scapy.layers.l2 import ARP, Ether

    pkt = Ether() / ARP(psrc="192.168.1.42", pdst="192.168.1.1", hwsrc="3C:52:82:1A:0F:22", op=1)
    model = PacketParser.parse(pkt)
    assert model.protocol == "ARP"
    assert "Who has 192.168.1.1" in model.info
