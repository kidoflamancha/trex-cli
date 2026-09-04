from __future__ import annotations

import pytest
import yaml
from pydantic import ValidationError

from trex_cli.models import MacVariation, SubmitBody
from trex_cli.yaml_loader import load_yaml

from .conftest import rfc_document, stateless_document


def test_unknown_fields_are_rejected() -> None:
    document = stateless_document()
    document["spec"]["surprise"] = True
    with pytest.raises(ValidationError):
        SubmitBody.model_validate({"document": document})


def test_broadcast_mac_is_rejected() -> None:
    document = stateless_document()
    document["spec"]["packet"]["ethernet"]["dst"] = "ff:ff:ff:ff:ff:ff"
    with pytest.raises(ValidationError):
        SubmitBody.model_validate({"document": document})


def test_dhcp_storm_document_rejects_forged_wire_size_and_mac_pool() -> None:
    document = {
        "apiVersion": "trex.example.io/v1",
        "kind": "PacketStorm",
        "spec": {
            "protocol": "dhcp",
            "safety": {"isolatedLab": True},
            "clients": {
                "role": "client",
                "port": "lab-west",
                "macStart": "00:00:00:00:00:01",
                "macEnd": "00:00:00:00:00:04",
                "count": 4,
            },
            "server": {"role": "server", "port": "lab-east"},
            "run": {
                "pps": 100,
                "wireSize": 64,
                "estimatedBpsL1": 67200,
                "duration": "3s",
            },
        },
    }
    with pytest.raises(ValidationError, match="DHCP Discover wire size"):
        SubmitBody.model_validate({"document": document})

    document["spec"]["run"] = {
        "pps": 100,
        "wireSize": 290,
        "estimatedBpsL1": 248000,
        "duration": "3s",
    }
    document["spec"]["clients"]["macEnd"] = "00:00:00:00:00:05"
    with pytest.raises(ValidationError, match="MAC pool"):
        SubmitBody.model_validate({"document": document})


def test_arp_storm_document_rejects_forged_wire_size_and_identity_pool() -> None:
    document = {
        "apiVersion": "trex.example.io/v1",
        "kind": "PacketStorm",
        "spec": {
            "protocol": "arp",
            "safety": {"isolatedLab": True},
            "senders": {
                "role": "client",
                "port": "lab-west",
                "macStart": "00:00:00:00:00:01",
                "macEnd": "00:00:00:00:00:04",
                "ipv4Start": "198.18.0.1",
                "ipv4End": "198.18.0.4",
                "count": 4,
            },
            "target": {"role": "server", "port": "lab-east", "ipv4": "198.19.0.1"},
            "run": {
                "pps": 100,
                "wireSize": 65,
                "estimatedBpsL1": 68000,
                "duration": "3s",
            },
        },
    }
    with pytest.raises(ValidationError, match="ARP Request wire size"):
        SubmitBody.model_validate({"document": document})

    document["spec"]["run"] = {
        "pps": 100,
        "wireSize": 64,
        "estimatedBpsL1": 67200,
        "duration": "3s",
    }
    document["spec"]["senders"]["ipv4End"] = "198.18.0.5"
    with pytest.raises(ValidationError, match="identity pool"):
        SubmitBody.model_validate({"document": document})


def test_mac_variation_is_normalized_and_must_stay_in_one_16_bit_prefix() -> None:
    document = stateless_document()
    document["spec"]["packet"]["ethernet"]["src"] = {
        "start": "00:00:00:00:00:01",
        "end": "00:00:00:00:00:04",
        "mode": "increment",
    }
    body = SubmitBody.model_validate({"document": document})
    source = body.document.spec.packet.ethernet.src
    assert isinstance(source, MacVariation)
    assert source.start == "00:00:00:00:00:01"

    document["spec"]["packet"]["ethernet"]["src"]["end"] = "00:01:00:00:00:04"
    with pytest.raises(ValidationError, match="16-bit prefix"):
        SubmitBody.model_validate({"document": document})


def test_duplicate_yaml_keys_are_rejected() -> None:
    with pytest.raises(yaml.constructor.ConstructorError):
        load_yaml("kind: StatelessTraffic\nkind: Rfc2544Throughput\n")


def test_duration_is_canonicalized_to_milliseconds() -> None:
    body = SubmitBody.model_validate({"document": stateless_document()})
    assert body.document.spec.duration == 30_000


def test_rfc2544_rejects_bare_l2_packet_without_isolated_flow_statistics() -> None:
    document = {
        "apiVersion": "trex.example.io/v1",
        "kind": "Rfc2544Throughput",
        "spec": {
            "safety": {"isolatedLab": True},
            "ports": {"tx": "lab-west", "rx": "lab-east"},
            "mode": "fast",
            "packet": {
                "ethernet": {"src": "00:00:00:00:00:01", "dst": "00:00:00:00:00:02"}
            },
        },
    }
    with pytest.raises(ValidationError, match="isolated flow statistics"):
        SubmitBody.model_validate({"document": document})


def test_rfc2544_suite_rejects_duplicate_tests_and_orphan_assertion() -> None:
    document = {
        "apiVersion": "trex.example.io/v1",
        "kind": "Rfc2544Suite",
        "spec": {
            "safety": {"isolatedLab": True},
            "ports": {"tx": "lab-west", "rx": "lab-east"},
            "mode": "fast",
            "tests": ["frame-loss", "frame-loss"],
            "packet": {
                "ethernet": {
                    "src": "00:00:00:00:00:01",
                    "dst": "00:00:00:00:00:02",
                },
                "ipv4": {"src": "198.18.0.1", "dst": "198.19.0.1"},
            },
        },
    }
    with pytest.raises(ValidationError, match="tests must be unique"):
        SubmitBody.model_validate({"document": document})

    document["spec"]["tests"] = ["frame-loss"]
    document["spec"]["assertion"] = {"minimumPercentLineRate": {"64": 90}}
    with pytest.raises(ValidationError, match="assertion requires"):
        SubmitBody.model_validate({"document": document})


def test_complete_strict_suite_requires_explicit_latency_and_back_to_back_settings() -> None:
    document = rfc_document()
    document["kind"] = "Rfc2544Suite"
    document["spec"]["tests"] = [
        "throughput",
        "latency",
        "frame-loss",
        "back-to-back",
    ]

    with pytest.raises(ValidationError, match="latency settings are required"):
        SubmitBody.model_validate({"document": document})


def test_latency_and_back_to_back_require_an_earlier_throughput_test() -> None:
    document = rfc_document()
    document["kind"] = "Rfc2544Suite"
    document["spec"]["tests"] = ["latency"]
    document["spec"].pop("assertion", None)
    document["spec"]["latency"] = {
        "definition": "store-and-forward",
        "scenarios": ["same-destination", "new-destination"],
    }

    with pytest.raises(ValidationError, match="throughput must run before latency"):
        SubmitBody.model_validate({"document": document})


def test_latency_can_freeze_an_explicit_new_destination_packet() -> None:
    document = rfc_document()
    document["kind"] = "Rfc2544Suite"
    document["spec"]["tests"] = ["throughput", "latency"]
    document["spec"]["latency"] = {
        "definition": "store-and-forward",
        "scenarios": ["same-destination", "new-destination"],
        "newDestinationPacket": {
            "ethernet": {"src": "00:00:00:00:00:01", "dst": "00:00:00:00:00:03"},
            "ipv4": {"src": "198.18.0.1", "dst": "198.19.1.1"},
            "udp": {"srcPort": 49152, "dstPort": 7},
        },
    }

    parsed = SubmitBody.model_validate({"document": document}).document
    assert parsed.kind == "Rfc2544Suite"
    assert parsed.spec.latency is not None
    assert parsed.spec.latency.new_destination_packet is not None
    assert parsed.spec.latency.new_destination_packet.ipv4 is not None
    assert parsed.spec.latency.new_destination_packet.ipv4.dst == "198.19.1.1"


@pytest.mark.parametrize(
    "path",
    [
        "examples/stateless-l2.yaml",
        "examples/stateless.yaml",
        "examples/rfc2544-throughput.yaml",
    ],
)
def test_examples_validate(path: str) -> None:
    document = load_yaml(__import__("pathlib").Path(path).read_text(encoding="utf-8"))
    SubmitBody.model_validate({"document": document})
