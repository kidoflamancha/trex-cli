from __future__ import annotations

import ipaddress

ARP_REQUEST_WIRE_SIZE = 64


def arp_sender_mac_end(mac_start: str, count: int) -> str:
    parts = mac_start.split(":")
    if len(parts) != 6 or any(len(part) != 2 for part in parts):
        raise ValueError("ARP sender MAC must contain six hexadecimal octets")
    try:
        start = int("".join(parts), 16)
    except ValueError as error:
        raise ValueError("ARP sender MAC must contain six hexadecimal octets") from error
    if start & (1 << 40):
        raise ValueError("ARP sender MAC must be unicast")
    if count < 1:
        raise ValueError("ARP sender count must be greater than zero")
    end = start + count - 1
    if end > 0xFFFF_FFFF_FFFF:
        raise ValueError("ARP sender MAC pool exceeds the Ethernet address space")
    if start >> 32 != end >> 32:
        raise ValueError("ARP sender MAC pool must keep the first two octets fixed")
    if end & (1 << 40):
        raise ValueError("ARP sender MAC pool must remain unicast")
    raw = f"{end:012x}"
    return ":".join(raw[index : index + 2] for index in range(0, 12, 2))


def arp_sender_ipv4_end(ipv4_start: str, count: int) -> str:
    try:
        start = ipaddress.IPv4Address(ipv4_start)
    except ipaddress.AddressValueError as error:
        raise ValueError("ARP sender IPv4 must be a valid IPv4 address") from error
    if count < 1:
        raise ValueError("ARP sender count must be greater than zero")
    end = int(start) + count - 1
    if end > 0xFFFF_FFFF:
        raise ValueError("ARP sender IPv4 pool exceeds the IPv4 address space")
    return str(ipaddress.IPv4Address(end))
