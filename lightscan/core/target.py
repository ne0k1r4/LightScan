"""
Target parser — turns whatever you typed into a clean list of IPs and ports.

Handles single IPs, CIDR ranges, hyphenated ranges (10.0.0.1-10),
hostnames, and file:// lists. Port specs accept comma-separated ports,
ranges (80-443), named lists (top100), or free-form combinations.
"""
import ipaddress, re, socket

TOP_100 = sorted(set([
    20,21,22,23,25,53,69,79,80,88,110,111,119,123,135,137,138,139,143,161,
    194,389,443,445,465,514,515,548,587,631,636,873,990,993,995,1080,1433,
    1521,1723,2049,2082,2083,2086,2087,3000,3128,3306,3389,4443,4848,5000,
    5432,5800,5900,6379,6443,7001,7443,8000,8080,8081,8443,8888,9000,9090,
    9200,9300,9443,10000,27017,
]))

def parse_targets(spec: str) -> list:
    if spec.startswith("file:"):
        targets = []
        with open(spec[5:]) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    targets.extend(parse_targets(line))
        return targets
    if "/" in spec:
        try:
            return [str(h) for h in ipaddress.ip_network(spec, strict=False).hosts()]
        except ValueError:
            pass
    m = re.match(r"^(\d+\.\d+\.\d+\.)(\d+)-(\d+)$", spec)
    if m:
        prefix = m.group(1)
        start = int(m.group(2))
        end = int(m.group(3))
        return [f"{prefix}{i}" for i in range(start, end + 1)]
    return [spec.strip()]

def parse_ports(spec: str) -> list:
    if spec.lower() in ("top100", "top-100"):
        return TOP_100
    ports = set()
    for part in spec.split(","):
        part = part.strip()
        if "-" in part and not part.startswith("-"):
            lo, hi = part.split("-", 1)
            ports.update(range(int(lo), int(hi) + 1))
        elif part.isdigit():
            ports.add(int(part))
    return sorted(ports)

def resolve(host: str):
    try:
        return socket.gethostbyname(host)
    except socket.gaierror:
        return None
# port range fix
# dns cache
# type hints
# port list fix
