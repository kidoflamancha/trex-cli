from trex_cli.address_policy import ipv4_range_allowed, mac_range_allowed


def test_ipv4_pool_rejects_holes_but_accepts_contiguous_network_union() -> None:
    assert not ipv4_range_allowed("10.0.0.1", "10.0.0.3", ["10.0.0.1/32", "10.0.0.3/32"])
    assert ipv4_range_allowed("10.0.0.1", "10.0.0.3", ["10.0.0.0/31", "10.0.0.2/31"])
    assert not ipv4_range_allowed("10.0.0.1", "10.0.0.3", ["::/0"])


def test_mac_pool_requires_one_covering_prefix() -> None:
    start, end = "02:00:00:00:00:01", "02:00:00:00:00:03"
    assert not mac_range_allowed(start, end, [start, end])
    assert mac_range_allowed(start, end, ["02:00:00"])
