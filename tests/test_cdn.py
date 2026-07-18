# tests for cdn.py and the --exclude-cdn host-splitting logic.
#
# naabu does the same check before deciding on a full port sweep - if a
# target resolves to a known cloudflare/fastly range, scanning 1000 ports
# against it is mostly just scanning their shared edge, not whatever's
# actually in scope. real ips used below are genuine addresses inside the
# published ranges (cloudflare.com/ips, api.fastly.com/public-ip-list),
# not made up.
from unittest.mock import patch

from lightscan.scan.cdn import is_cdn_ip, CDN_RANGES
from lightscan.cli import _split_cdn_hosts


def test_cloudflare_ipv4_detected():
    matched, provider = is_cdn_ip("104.16.1.1")  # inside 104.16.0.0/13
    assert matched and provider == "cloudflare"


def test_cloudflare_second_range_detected():
    matched, provider = is_cdn_ip("172.64.1.1")  # inside 172.64.0.0/13
    assert matched and provider == "cloudflare"


def test_fastly_detected():
    matched, provider = is_cdn_ip("151.101.1.1")  # inside 151.101.0.0/16
    assert matched and provider == "fastly"


def test_cloudflare_ipv6_detected():
    matched, provider = is_cdn_ip("2606:4700:1::1")  # inside 2606:4700::/32
    assert matched and provider == "cloudflare"


def test_ordinary_ip_not_flagged():
    assert is_cdn_ip("8.8.8.8") == (False, "")


def test_private_range_not_flagged():
    assert is_cdn_ip("10.0.4.12") == (False, "")


def test_garbage_input_doesnt_crash():
    assert is_cdn_ip("not-an-ip") == (False, "")
    assert is_cdn_ip("") == (False, "")


def test_all_shipped_ranges_actually_parse():
    # catches a typo'd cidr before it ships, not after
    import ipaddress
    for provider, cidrs in CDN_RANGES.items():
        for cidr in cidrs:
            ipaddress.ip_network(cidr)  # raises ValueError if malformed


# ── _split_cdn_hosts() ───────────────────────────────────────────────────

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
    # resolve() failing shouldn't crash the split or silently drop the host
    with patch("lightscan.cli.resolve", return_value=None):
        normal, cdn = _split_cdn_hosts(["doesnt-resolve.invalid"])
    assert normal == ["doesnt-resolve.invalid"]
    assert cdn == []
