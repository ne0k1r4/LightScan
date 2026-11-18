"""Email harvesting from web pages via crawling and regex extraction."""
from __future__ import annotations

import asyncio
import re
import urllib.error
import urllib.parse
import urllib.request
from html.parser import HTMLParser

from lightscan.core.models import Confidence, ScanResult, Severity

EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}")

COMMON_PAGES = [
    "/contact", "/about", "/team", "/staff", "/people",
    "/privacy", "/imprint",
]

FALSE_POSITIVES = {
    "example@example.com",
    "user@domain.tld",
    "user@domain.com",
    "user@example.com",
    "email@example.com",
    "test@test.com",
    "name@domain.com",
    "someone@example.com",
    "your@email.com",
    "info@example.com",
    "name@example.com",
    "youremail@domain.com",
}

ROLE_PREFIXES = {
    "admin", "info", "support", "security", "postmaster",
    "webmaster", "abuse", "noc", "hostmaster", "sales",
}


class _LinkExtractor(HTMLParser):
    def __init__(self, base_url: str):
        super().__init__()
        self.base = base_url
        self.links: list[str] = []
        self.emails: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag == "a":
            for attr_name, attr_val in attrs:
                if attr_name == "href" and attr_val:
                    if attr_val.startswith("mailto:"):
                        email = attr_val[7:].split("?")[0].strip()
                        if email:
                            self.emails.append(email.lower())
                    else:
                        full = urllib.parse.urljoin(self.base, attr_val)
                        self.links.append(full)


def _fetch_page(url: str, timeout: float) -> str:
    try:
        req = urllib.request.Request(
            url,
            headers={
                "User-Agent": "Mozilla/5.0 (compatible; LightScan/2.0; +security-audit)",
                "Accept": "text/html",
            },
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = resp.read(1024 * 512)
            return data.decode("utf-8", "replace")
    except Exception:
        return ""


def _extract_emails(html: str) -> set[str]:
    found = set()
    for match in EMAIL_RE.finditer(html):
        email = match.group().lower().rstrip(".")
        if email not in FALSE_POSITIVES:
            found.add(email)
    return found


def _is_same_domain(url: str, base_domain: str) -> bool:
    try:
        parsed = urllib.parse.urlparse(url)
        return parsed.hostname is not None and (
            parsed.hostname == base_domain
            or parsed.hostname.endswith("." + base_domain)
        )
    except Exception:
        return False


def _blocking_harvest(url: str, max_pages: int, timeout: float) -> list[dict]:
    parsed_base = urllib.parse.urlparse(url)
    base_domain = parsed_base.hostname or ""
    base_url = f"{parsed_base.scheme}://{parsed_base.netloc}"

    all_emails: set[str] = set()
    visited: set[str] = set()
    queue: list[str] = [url]

    for page_path in COMMON_PAGES:
        common_url = base_url + page_path
        if common_url not in queue:
            queue.append(common_url)

    pages_fetched = 0
    while queue and pages_fetched < max_pages:
        current = queue.pop(0)
        if current in visited:
            continue
        visited.add(current)
        pages_fetched += 1

        html = _fetch_page(current, timeout)
        if not html:
            continue

        all_emails.update(_extract_emails(html))

        try:
            extractor = _LinkExtractor(current)
            extractor.feed(html)
            for email in extractor.emails:
                email = email.lower().rstrip(".")
                if email not in FALSE_POSITIVES:
                    all_emails.add(email)
            for link in extractor.links:
                if link not in visited and _is_same_domain(link, base_domain):
                    link_clean = link.split("#")[0].split("?")[0]
                    if link_clean not in visited and link_clean not in queue:
                        queue.append(link_clean)
        except Exception:
            pass

    result_list: list[dict] = []
    for email in sorted(all_emails):
        local_part = email.split("@")[0].lower()
        is_role = local_part in ROLE_PREFIXES
        result_list.append({
            "email": email,
            "role_account": is_role,
        })
    return result_list


async def email_harvest_async(
    url: str,
    max_pages: int = 50,
    timeout: float = 8.0,
) -> list[ScanResult]:
    """Crawl target website and extract email addresses."""
    results: list[ScanResult] = []
    try:
        findings = await asyncio.to_thread(_blocking_harvest, url, max_pages, timeout)
    except Exception:
        return results

    role_emails = []
    for item in findings:
        sev = Severity.INFO
        detail = f"Email found: {item['email']}"
        if item["role_account"]:
            detail += " (role-based account)"
            role_emails.append(item["email"])
        results.append(ScanResult(
            module="recon-email",
            target=url,
            port=0,
            status="found",
            severity=sev,
            detail=detail,
            data=item,
            confidence=Confidence.CERTAIN,
        ))

    if findings:
        summary_detail = f"Harvested {len(findings)} unique email(s) from {url}"
        if role_emails:
            summary_detail += f" — {len(role_emails)} role-based account(s) found (spear-phishing risk)"
        results.append(ScanResult(
            module="recon-email",
            target=url,
            port=0,
            status="summary",
            severity=Severity.LOW if role_emails else Severity.INFO,
            detail=summary_detail,
            data={"total": len(findings), "role_emails": role_emails},
            confidence=Confidence.CERTAIN,
        ))

    return results
