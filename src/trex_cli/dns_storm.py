from __future__ import annotations

import re
import struct
from typing import Literal

_LABEL_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")
_QUERY_TYPE = {"A": 1, "AAAA": 28}


def normalize_dns_name(value: str) -> str:
    candidate = value[:-1] if value.endswith(".") else value
    labels = candidate.split(".")
    if not candidate or any(not _LABEL_RE.fullmatch(label) for label in labels):
        raise ValueError("DNS name must contain valid ASCII host labels")
    encoded_length = sum(len(label.encode("ascii")) + 1 for label in labels) + 1
    if encoded_length > 255:
        raise ValueError("DNS name exceeds the 255-byte wire limit")
    return candidate.lower() + "."


def encode_dns_query(
    name: str,
    query_type: Literal["A", "AAAA"],
    *,
    recursion_desired: bool,
    transaction_id: int = 0,
) -> bytes:
    normalized = normalize_dns_name(name)
    labels = normalized[:-1].split(".")
    question_name = (
        b"".join(bytes([len(label)]) + label.encode("ascii") for label in labels) + b"\0"
    )
    flags = 0x0100 if recursion_desired else 0
    header = struct.pack("!HHHHHH", transaction_id, flags, 1, 0, 0, 0)
    question = question_name + struct.pack("!HH", _QUERY_TYPE[query_type], 1)
    return header + question


def dns_query_wire_size(payload: bytes) -> int:
    return max(64, 4 + 14 + 20 + 8 + len(payload))
