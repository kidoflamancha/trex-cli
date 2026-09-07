"""Shared authorization of complete generated address ranges."""

import ipaddress


def ipv4_range_allowed(start: str, end: str, cidrs: list[str]) -> bool:
    first, last = int(ipaddress.IPv4Address(start)), int(ipaddress.IPv4Address(end))
    if first > last:
        return False
    intervals = sorted(
        (int(network.network_address), int(network.broadcast_address))
        for cidr in cidrs
        if isinstance(network := ipaddress.ip_network(cidr, strict=False), ipaddress.IPv4Network)
    )
    cursor = first
    for lower, upper in intervals:
        if upper < cursor:
            continue
        if lower > cursor:
            return False
        cursor = upper + 1
        if cursor > last:
            return True
    return False


def mac_range_allowed(start: str, end: str, prefixes: list[str]) -> bool:
    return any(
        start.lower().startswith(prefix.lower()) and end.lower().startswith(prefix.lower())
        for prefix in prefixes
    )
