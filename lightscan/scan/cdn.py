# cdn.py — is this ip actually a cdn/waf edge, not the real origin

# naabu does the same check before deciding whether a full port sweep is
# worth it. scanning a cloudflare or fastly IP for 1000 ports is mostly
# scanning cloudflare/fastly's own infra, not the client's - slow, and a
# good way to get flagged by someone else's abuse detection for a target
# that was never actually in scope to begin with.

# ranges pulled straight from each provider's own published list (not a
# third-party aggregator) as of when this was written:
# cloudflare: https://www.cloudflare.com/ips/
# fastly:     https://api.fastly.com/public-ip-list

# deliberately NOT trying to cover every CDN out there - akamai doesn't
# publish a clean official range list the same way, and AWS CloudFront's
# ranges are buried in their huge shared ip-ranges.json across every AWS
# service, not CloudFront-specific. cloudflare + fastly alone already
# covers a big chunk of what actually shows up in real engagements.
# add more providers here as their own dict entry if needed later.
import ipaddress

CDN_RANGES: dict[str, list[str]] = {
    "cloudflare": [
        "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
        "104.16.0.0/13",   "104.24.0.0/14",   "108.162.192.0/18",
        "131.0.72.0/22",   "141.101.64.0/18", "162.158.0.0/15",
        "172.64.0.0/13",   "173.245.48.0/20", "188.114.96.0/20",
        "190.93.240.0/20", "197.234.240.0/22","198.41.128.0/17",
        "2400:cb00::/32",  "2606:4700::/32",  "2803:f800::/32",
        "2405:b500::/32",  "2405:8100::/32",  "2a06:98c0::/29",
        "2c0f:f248::/32",
    ],
    "fastly": [
        "23.235.32.0/20",  "43.249.72.0/22",   "103.244.50.0/24",
        "103.245.222.0/23","103.245.224.0/24", "104.156.80.0/20",
        "140.248.64.0/18", "140.248.128.0/17", "146.75.0.0/17",
        "151.101.0.0/16",  "157.52.64.0/18",   "167.82.0.0/17",
        "167.82.128.0/20", "167.82.160.0/20",  "167.82.224.0/20",
        "172.111.64.0/18", "185.31.16.0/22",   "199.27.72.0/21",
        "199.232.0.0/16",  "2a04:4e40::/32",   "2a04:4e42::/32",
    ],
}

# parse once at import time instead of re-parsing every string on every
# lookup - this runs per-target, not just once per scan
_PARSED: list[tuple] = []
for _provider, _cidrs in CDN_RANGES.items():
    for _cidr in _cidrs:
        _PARSED.append((ipaddress.ip_network(_cidr), _provider))

def is_cdn_ip(ip: str) -> tuple[bool, str]:
    """(True, provider) if ip falls inside a known cdn/waf range, else (False, "")"""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False, ""  # hostname slipped through unresolved, or garbage input
    for net, provider in _PARSED:
        if addr in net:
            return True, provider
    return False, ""
