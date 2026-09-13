from unittest.mock import patch

from lightscan.scan.cdn import is_cdn_ip, CDN_RANGES
from lightscan.cli import _split_cdn_hosts

def test_cloudflare_ipv4_detected():
    matched, provider = is_cdn_ip("104.16.1.1")
    assert matched and provider == "cloudflare"

def test_cloudflare_second_range_detected():
    matched, provider = is_cdn_ip("172.64.1.1")
    assert matched and provider == "cloudflare"

def test_fastly_detected():
    matched, provider = is_cdn_ip("151.101.1.1")
    assert matched and provider == "fastly"

def test_cloudflare_ipv6_detected():
    matched, provider = is_cdn_ip("2606:4700:1::1")
    assert matched and provider == "cloudflare"

def test_ordinary_ip_not_flagged():
    assert is_cdn_ip("8.8.8.8") == (False, "")

def test_private_range_not_flagged():
    assert is_cdn_ip("10.0.4.12") == (False, "")

def test_garbage_input_doesnt_crash():
    assert is_cdn_ip("not-an-ip") == (False, "")
    assert is_cdn_ip("") == (False, "")

def test_all_shipped_ranges_actually_parse():
    import ipaddress
    for provider, cidrs in CDN_RANGES.items():
        for cidr in cidrs:
            ipaddress.ip_network(cidr)

def test_split_puts_cdn_host_in_cdn_bucket():
    with patch("lightscan.cli.resolve", side_effect=lambda h: {"cf.example.com": "104.16.1.1",
                                                                  "origin.example.com": "10.0.4.12"}[h]):
        normal, cdn = _split_cdn_hosts(["cf.example.com", "origin.example.com"])
    assert normal == ["origin.example.com"]
    assert cdn == ["cf.example.com"]

def test_split_all_normal_when_nothing_matches():
    with patch("lightscan.cli.resolve", return_value="10.0.4.12"):
        normal, cdn = _split_cdn_hosts(["a.example.com", "b.example.com"])
    assert len(normal) == 2
    assert cdn == []

def test_split_unresolvable_host_falls_back_to_normal():
    with patch("lightscan.cli.resolve", return_value=None):
        normal, cdn = _split_cdn_hosts(["doesnt-resolve.invalid"])
    assert normal == ["doesnt-resolve.invalid"]
    assert cdn == []
