from __future__ import annotations


def parse_unicast_mac(value: str) -> int:
    parts = value.split(":")
    if len(parts) != 6 or any(
        len(part) != 2 or any(char not in "0123456789abcdefABCDEF" for char in part)
        for part in parts
    ):
        raise ValueError("DHCP client MAC must contain six hexadecimal octets")
    numeric = int("".join(parts), 16)
    if numeric & (1 << 40):
        raise ValueError("DHCP client MAC must be unicast")
    return numeric


def format_mac(value: int) -> str:
    if not 0 <= value < 1 << 48:
        raise ValueError("DHCP client MAC pool exceeds the Ethernet address space")
    encoded = value.to_bytes(6, "big")
    return ":".join(f"{octet:02x}" for octet in encoded)


def dhcp_client_mac_end(start: str, count: int) -> str:
    if count < 1:
        raise ValueError("DHCP client count must be greater than zero")
    first = parse_unicast_mac(start)
    last = first + count - 1
    if last >= 1 << 48:
        raise ValueError("DHCP client MAC pool exceeds the Ethernet address space")
    if first >> 32 != last >> 32:
        raise ValueError("DHCP client MAC pool must keep the first two octets fixed")
    if last & (1 << 40):
        raise ValueError("DHCP client MAC pool must remain unicast")
    return format_mac(last)


def encode_dhcp_discover(client_mac: str, *, transaction_id: int = 0) -> bytes:
    if not 0 <= transaction_id <= 0xFFFF_FFFF:
        raise ValueError("DHCP transaction ID must fit in 32 bits")
    mac = parse_unicast_mac(client_mac).to_bytes(6, "big")
    bootp = bytearray(236)
    bootp[0:4] = bytes((1, 1, 6, 0))  # BOOTREQUEST, Ethernet, MAC length, no relay hops
    bootp[4:8] = transaction_id.to_bytes(4, "big")
    bootp[10:12] = (0x8000).to_bytes(2, "big")  # request a broadcast reply
    bootp[28:34] = mac
    return bytes(bootp) + b"\x63\x82\x53\x63\x35\x01\x01\xff"


def dhcp_discover_wire_size(payload: bytes) -> int:
    return max(64, 4 + 14 + 20 + 8 + len(payload))
