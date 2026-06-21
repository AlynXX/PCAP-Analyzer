from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import ipaddress
import struct
from typing import Iterator


ETHERNET = 1
PCAPNG_SHB = b"\x0a\x0d\x0d\x0a"


@dataclass(frozen=True)
class RawPacket:
    timestamp: float
    data: bytes
    link_type: int


@dataclass(frozen=True)
class ParsedPacket:
    timestamp: float
    length: int
    link_type: int
    l2_protocol: str | None = None
    src_ip: str | None = None
    dst_ip: str | None = None
    ip_version: int | None = None
    transport: str | None = None
    application: str | None = None
    src_port: int | None = None
    dst_port: int | None = None
    tcp_flags: int | None = None
    icmp_type: int | None = None

    @property
    def protocol_label(self) -> str:
        if self.application:
            return self.application
        if self.transport:
            return self.transport
        if self.l2_protocol:
            return self.l2_protocol
        return "UNKNOWN"


def read_packets(path: str | Path) -> Iterator[RawPacket]:
    data = Path(path).read_bytes()
    if data.startswith(PCAPNG_SHB):
        yield from _read_pcapng(data)
        return
    yield from _read_pcap(data)


def parse_packet(raw: RawPacket) -> ParsedPacket:
    if raw.link_type != ETHERNET:
        return ParsedPacket(raw.timestamp, len(raw.data), raw.link_type, l2_protocol=f"LINKTYPE_{raw.link_type}")
    return _parse_ethernet(raw)


def _read_pcap(data: bytes) -> Iterator[RawPacket]:
    if len(data) < 24:
        raise ValueError("Plik PCAP jest za krotki.")

    magic = data[:4]
    formats = {
        b"\xd4\xc3\xb2\xa1": ("<", 1_000_000),
        b"\xa1\xb2\xc3\xd4": (">", 1_000_000),
        b"\x4d\x3c\xb2\xa1": ("<", 1_000_000_000),
        b"\xa1\xb2\x3c\x4d": (">", 1_000_000_000),
    }
    if magic not in formats:
        raise ValueError("Nie rozpoznano formatu PCAP/PCAPNG.")

    endian, resolution = formats[magic]
    _version_major, _version_minor, _thiszone, _sigfigs, _snaplen, network = struct.unpack(
        f"{endian}HHiiii", data[4:24]
    )

    offset = 24
    while offset + 16 <= len(data):
        ts_sec, ts_frac, incl_len, _orig_len = struct.unpack(f"{endian}IIII", data[offset : offset + 16])
        offset += 16
        packet = data[offset : offset + incl_len]
        if len(packet) != incl_len:
            raise ValueError("Uszkodzony rekord pakietu PCAP.")
        offset += incl_len
        yield RawPacket(ts_sec + (ts_frac / resolution), packet, network)


def _read_pcapng(data: bytes) -> Iterator[RawPacket]:
    offset = 0
    endian = "<"
    interfaces: dict[int, int] = {}

    while offset + 12 <= len(data):
        block_type = data[offset : offset + 4]
        if block_type == PCAPNG_SHB:
            bom = data[offset + 8 : offset + 12]
            if bom == b"\x4d\x3c\x2b\x1a":
                endian = "<"
            elif bom == b"\x1a\x2b\x3c\x4d":
                endian = ">"
            else:
                raise ValueError("Niepoprawny znacznik kolejnosci bajtow PCAPNG.")
        block_len = struct.unpack(f"{endian}I", data[offset + 4 : offset + 8])[0]
        if block_len < 12 or offset + block_len > len(data):
            raise ValueError("Uszkodzony blok PCAPNG.")
        body = data[offset + 8 : offset + block_len - 4]

        if block_type == PCAPNG_SHB:
            interfaces.clear()
        elif block_type == struct.pack(f"{endian}I", 1):  # Interface Description Block
            if len(body) >= 8:
                link_type = struct.unpack(f"{endian}H", body[:2])[0]
                interfaces[len(interfaces)] = link_type
        elif block_type == struct.pack(f"{endian}I", 6):  # Enhanced Packet Block
            if len(body) >= 20:
                interface_id, ts_high, ts_low, captured_len, _packet_len = struct.unpack(f"{endian}IIIII", body[:20])
                packet = body[20 : 20 + captured_len]
                timestamp = ((ts_high << 32) | ts_low) / 1_000_000
                yield RawPacket(timestamp, packet, interfaces.get(interface_id, ETHERNET))
        elif block_type == struct.pack(f"{endian}I", 3):  # Simple Packet Block
            if len(body) >= 4:
                packet_len = struct.unpack(f"{endian}I", body[:4])[0]
                yield RawPacket(0.0, body[4 : 4 + packet_len], ETHERNET)

        offset += block_len


def _parse_ethernet(raw: RawPacket) -> ParsedPacket:
    data = raw.data
    if len(data) < 14:
        return ParsedPacket(raw.timestamp, len(data), raw.link_type, l2_protocol="ETHERNET_TRUNCATED")

    ether_type = struct.unpack("!H", data[12:14])[0]
    payload_offset = 14
    if ether_type == 0x8100 and len(data) >= 18:
        ether_type = struct.unpack("!H", data[16:18])[0]
        payload_offset = 18

    if ether_type == 0x0800:
        return _parse_ipv4(raw, payload_offset)
    if ether_type == 0x86DD:
        return _parse_ipv6(raw, payload_offset)
    if ether_type == 0x0806:
        return ParsedPacket(raw.timestamp, len(data), raw.link_type, l2_protocol="ARP")
    return ParsedPacket(raw.timestamp, len(data), raw.link_type, l2_protocol=f"ETHERTYPE_0x{ether_type:04x}")


def _parse_ipv4(raw: RawPacket, offset: int) -> ParsedPacket:
    data = raw.data
    if len(data) < offset + 20:
        return ParsedPacket(raw.timestamp, len(data), raw.link_type, l2_protocol="IPv4_TRUNCATED")

    first = data[offset]
    ihl = (first & 0x0F) * 4
    if len(data) < offset + ihl or ihl < 20:
        return ParsedPacket(raw.timestamp, len(data), raw.link_type, l2_protocol="IPv4_TRUNCATED")

    proto = data[offset + 9]
    src_ip = str(ipaddress.IPv4Address(data[offset + 12 : offset + 16]))
    dst_ip = str(ipaddress.IPv4Address(data[offset + 16 : offset + 20]))
    return _parse_transport(raw, "IPv4", 4, src_ip, dst_ip, proto, offset + ihl)


def _parse_ipv6(raw: RawPacket, offset: int) -> ParsedPacket:
    data = raw.data
    if len(data) < offset + 40:
        return ParsedPacket(raw.timestamp, len(data), raw.link_type, l2_protocol="IPv6_TRUNCATED")

    next_header = data[offset + 6]
    src_ip = str(ipaddress.IPv6Address(data[offset + 8 : offset + 24]))
    dst_ip = str(ipaddress.IPv6Address(data[offset + 24 : offset + 40]))
    return _parse_transport(raw, "IPv6", 6, src_ip, dst_ip, next_header, offset + 40)


def _parse_transport(
    raw: RawPacket,
    l2_protocol: str,
    ip_version: int,
    src_ip: str,
    dst_ip: str,
    proto: int,
    offset: int,
) -> ParsedPacket:
    data = raw.data
    if proto == 6 and len(data) >= offset + 20:
        src_port, dst_port = struct.unpack("!HH", data[offset : offset + 4])
        flags = data[offset + 13]
        application = _application_protocol("TCP", src_port, dst_port)
        return ParsedPacket(
            raw.timestamp,
            len(data),
            raw.link_type,
            l2_protocol,
            src_ip,
            dst_ip,
            ip_version,
            "TCP",
            application,
            src_port,
            dst_port,
            flags,
        )
    if proto == 17 and len(data) >= offset + 8:
        src_port, dst_port = struct.unpack("!HH", data[offset : offset + 4])
        application = _application_protocol("UDP", src_port, dst_port)
        return ParsedPacket(raw.timestamp, len(data), raw.link_type, l2_protocol, src_ip, dst_ip, ip_version, "UDP", application, src_port, dst_port)
    if proto == 1 and len(data) >= offset + 1:
        return ParsedPacket(raw.timestamp, len(data), raw.link_type, l2_protocol, src_ip, dst_ip, ip_version, "ICMP", icmp_type=data[offset])
    if proto == 58 and len(data) >= offset + 1:
        return ParsedPacket(raw.timestamp, len(data), raw.link_type, l2_protocol, src_ip, dst_ip, ip_version, "ICMPv6", icmp_type=data[offset])
    return ParsedPacket(raw.timestamp, len(data), raw.link_type, l2_protocol, src_ip, dst_ip, ip_version, f"IP_PROTO_{proto}")


def _application_protocol(transport: str, src_port: int, dst_port: int) -> str | None:
    tcp_ports = {
        20: "FTP-DATA",
        21: "FTP",
        22: "SSH",
        23: "Telnet",
        25: "SMTP",
        53: "DNS",
        80: "HTTP",
        110: "POP3",
        143: "IMAP",
        443: "HTTPS",
        445: "SMB",
        587: "SMTP",
        993: "IMAPS",
        995: "POP3S",
        1433: "MSSQL",
        3306: "MySQL",
        3389: "RDP",
        5432: "PostgreSQL",
        5900: "VNC",
        8080: "HTTP-ALT",
    }
    udp_ports = {
        53: "DNS",
        67: "DHCP",
        68: "DHCP",
        69: "TFTP",
        123: "NTP",
        137: "NetBIOS",
        138: "NetBIOS",
        161: "SNMP",
        162: "SNMP",
        500: "IKE",
        1900: "SSDP",
        5353: "mDNS",
    }
    ports = tcp_ports if transport == "TCP" else udp_ports
    return ports.get(dst_port) or ports.get(src_port)
