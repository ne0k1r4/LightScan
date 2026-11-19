"""
LightScan
Developer: Light (Neok1ra)
"""
from __future__ import annotations

TAXONOMY_MAP: dict[str, dict[str, str]] = {
    # Injection vulnerabilities
    "web-cmdi": {
        "cwe": "CWE-78: OS Command Injection",
        "owasp": "A03:2021-Injection",
        "remediation": "Avoid invoking shell interpreters. Pass structured argument vectors to APIs like execve or subprocess without shell=True, and validate input against a strict allowlist.",
    },
    "web-sqli": {
        "cwe": "CWE-89: SQL Injection",
        "owasp": "A03:2021-Injection",
        "remediation": "Use parameterized queries with prepared statements or an Object-Relational Mapper (ORM). Ensure all user input is bound rather than concatenated into queries.",
    },
    "web-sqli-post": {
        "cwe": "CWE-89: SQL Injection",
        "owasp": "A03:2021-Injection",
        "remediation": "Use parameterized queries with prepared statements or an ORM for all form-handling backend handlers.",
    },
    "web-sqli-blind": {
        "cwe": "CWE-89: Blind SQL Injection",
        "owasp": "A03:2021-Injection",
        "remediation": "Ensure database queries use parameterized inputs. Disallow dynamic SQL generation in conditional clauses.",
    },
    "web-sqli-union": {
        "cwe": "CWE-89: SQL Injection",
        "owasp": "A03:2021-Injection",
        "remediation": "Enforce strict parameterized queries. Prevent direct query concatenation in column selection or ordering clauses.",
    },
    "web-ssti": {
        "cwe": "CWE-1336: Server-Side Template Injection",
        "owasp": "A03:2021-Injection",
        "remediation": "Never concatenate user input directly into template strings. Pass dynamic data as context parameters to templates, or run template rendering in sandboxed mode.",
    },
    "web-crlf": {
        "cwe": "CWE-113: HTTP Response Splitting",
        "owasp": "A03:2021-Injection",
        "remediation": "Strip carriage return (\\r) and line feed (\\n) characters from all user input before writing values into HTTP response headers.",
    },

    # Broken Access Control & Traversal
    "web-path-traversal": {
        "cwe": "CWE-22: Path Traversal",
        "owasp": "A01:2021-Broken Access Control",
        "remediation": "Use an allowlist of permitted filenames or access files by an indirect ID. Resolve canonical paths (os.path.realpath) and verify they remain within the intended root directory.",
    },
    "web-lfi": {
        "cwe": "CWE-98: PHP File Inclusion",
        "owasp": "A01:2021-Broken Access Control",
        "remediation": "Disallow dynamic inclusion of file paths based on untrusted input. Disable allow_url_include and isolate uploaded files from script execution paths.",
    },
    "web-ssrf": {
        "cwe": "CWE-918: Server-Side Request Forgery",
        "owasp": "A10:2021-Server-Side Request Forgery (SSRF)",
        "remediation": "Validate and filter destination URLs against a strict domain allowlist. Block requests targeting loopback (127.0.0.1, ::1) and cloud metadata services (169.254.169.254).",
    },
    "web-idor": {
        "cwe": "CWE-639: Insecure Direct Object Reference",
        "owasp": "A01:2021-Broken Access Control",
        "remediation": "Enforce server-side record ownership checks on every request. Verify that the authenticated user has explicit permission to view or modify the requested resource ID.",
    },
    "web-subdomain-takeover": {
        "cwe": "CWE-284: Improper Access Control",
        "owasp": "A01:2021-Broken Access Control",
        "remediation": "Audit DNS records and remove stale or dangling CNAME entries that point to unmapped or decommissioned cloud services.",
    },
    "web-cors": {
        "cwe": "CWE-942: Overly Permissive CORS Policy",
        "owasp": "A01:2021-Broken Access Control",
        "remediation": "Avoid echoing the request Origin header. Maintain a strict allowlist of authorized origins and avoid combining Access-Control-Allow-Credentials: true with wildcard/reflected origins.",
    },
    "web-csrf": {
        "cwe": "CWE-352: Cross-Site Request Forgery",
        "owasp": "A01:2021-Broken Access Control",
        "remediation": "Implement unique, cryptographically strong anti-CSRF tokens for all state-changing requests, and configure SameSite=Lax or SameSite=Strict on session cookies.",
    },
    "web-open-redirect": {
        "cwe": "CWE-601: URL Redirection to Untrusted Site",
        "owasp": "A01:2021-Broken Access Control",
        "remediation": "Use relative path redirection or validate destination URLs against an allowlist of approved domains.",
    },
    "web-redirect": {
        "cwe": "CWE-601: URL Redirection to Untrusted Site",
        "owasp": "A01:2021-Broken Access Control",
        "remediation": "Use relative path redirection or validate destination URLs against an allowlist of approved domains.",
    },

    # Cross-Site Scripting
    "web-xss": {
        "cwe": "CWE-79: Reflected Cross-Site Scripting",
        "owasp": "A03:2021-Injection",
        "remediation": "Apply context-aware output encoding (HTML, JavaScript, URL, CSS) before rendering dynamic input in web responses. Deploy a robust Content-Security-Policy (CSP).",
    },
    "web-xss-stored": {
        "cwe": "CWE-79: Stored Cross-Site Scripting",
        "owasp": "A03:2021-Injection",
        "remediation": "Sanitize and contextualize all stored user input prior to HTML rendering. Deploy a strict Content-Security-Policy (CSP) that disables unsafe-inline.",
    },
    "web-xss-dom": {
        "cwe": "CWE-79: DOM-based Cross-Site Scripting",
        "owasp": "A03:2021-Injection",
        "remediation": "Avoid passing untrusted values to dangerous execution sinks like eval(), innerHTML, or document.write(). Use textContent or safe DOM APIs.",
    },

    # Authentication & Session Management
    "web-jwt-none": {
        "cwe": "CWE-347: Improper Verification of Cryptographic Signature",
        "owasp": "A07:2021-Identification and Authentication Failures",
        "remediation": "Reject JWT tokens with alg: none. Explicitly verify token signatures using a trusted server-side signing key and enforce expected algorithm types.",
    },
    "web-jwt-advanced": {
        "cwe": "CWE-347: Improper Verification of Cryptographic Signature",
        "owasp": "A07:2021-Identification and Authentication Failures",
        "remediation": "Ensure high-entropy secret keys are used for HMAC signatures (minimum 256 bits). Enforce strict signature algorithm verification on the backend.",
    },
    "web-oauth": {
        "cwe": "CWE-287: Improper Authentication",
        "owasp": "A07:2021-Identification and Authentication Failures",
        "remediation": "Enforce strict redirect_uri exact matching, enforce the state parameter for CSRF mitigation, and require PKCE for OAuth 2.0 authorization flows.",
    },
    "web-default-creds": {
        "cwe": "CWE-1392: Use of Default Credentials",
        "owasp": "A07:2021-Identification and Authentication Failures",
        "remediation": "Mandate unique passwords on initial setup, disable default vendor accounts, and enforce multi-factor authentication (MFA) on administrative portals.",
    },
    "web-cookie": {
        "cwe": "CWE-614: Sensitive Cookie in HTTPS Session Without 'Secure' Attribute",
        "owasp": "A05:2021-Security Misconfiguration",
        "remediation": "Set Secure, HttpOnly, and SameSite=Lax (or Strict) attributes on all authentication and session management cookies.",
    },

    # Security Misconfigurations & Information Disclosure
    "web-sec-headers": {
        "cwe": "CWE-693: Protection Mechanism Failure",
        "owasp": "A05:2021-Security Misconfiguration",
        "remediation": "Deploy missing baseline security headers: Content-Security-Policy, Strict-Transport-Security (HSTS), X-Content-Type-Options: nosniff, and X-Frame-Options: DENY.",
    },
    "web-clickjacking": {
        "cwe": "CWE-1021: Improper Restriction of Rendered UI Layers",
        "owasp": "A05:2021-Security Misconfiguration",
        "remediation": "Configure X-Frame-Options: DENY or frame-ancestors 'none' in Content-Security-Policy to prevent unauthorized framing.",
    },
    "web-sensitive-file": {
        "cwe": "CWE-552: Files or Directories Accessible to External Parties",
        "owasp": "A05:2021-Security Misconfiguration",
        "remediation": "Restrict web server access to configuration files, repository metadata (.git), environment files (.env), and database dumps in web server rules.",
    },
    "web-secret": {
        "cwe": "CWE-798: Use of Hard-coded Credentials",
        "owasp": "A07:2021-Identification and Authentication Failures",
        "remediation": "Remove hardcoded API keys, tokens, and credentials from client-side JavaScript. Store secrets in environment variables or a dedicated secret manager.",
    },
    "web-error-disclose": {
        "cwe": "CWE-209: Generation of Error Message Containing Sensitive Information",
        "owasp": "A05:2021-Security Misconfiguration",
        "remediation": "Disable detailed debug output and stack traces in production environments. Implement generic custom error pages.",
    },
    "web-xxe": {
        "cwe": "CWE-611: Improper Restriction of XML External Entity Reference",
        "owasp": "A05:2021-Security Misconfiguration",
        "remediation": "Disable external entity resolution (DTD / external entities) and XInclude in all XML parsers and document builders.",
    },
    "web-deserialize": {
        "cwe": "CWE-502: Deserialization of Untrusted Data",
        "owasp": "A08:2021-Software and Data Integrity Failures",
        "remediation": "Avoid deserializing untrusted byte streams (e.g. pickle, Java serialization, PHP unserialize). Use safe data serialization formats like JSON or Protocol Buffers.",
    },
    "web-proto-poll": {
        "cwe": "CWE-1321: Improperly Controlled Modification of Object Prototype Attributes",
        "owasp": "A03:2021-Injection",
        "remediation": "Freeze Object.prototype, validate property names against '__proto__' and 'constructor', or use Map instead of plain object lookup tables.",
    },
    "web-smuggling": {
        "cwe": "CWE-444: Inconsistent Interpretation of HTTP Requests",
        "owasp": "A04:2021-Insecure Design",
        "remediation": "Normalize HTTP request parsing across frontend reverse proxies and backend application servers. Prefer HTTP/2 end-to-end to eliminate ambiguity.",
    },
    "web-rate-limit": {
        "cwe": "CWE-307: Improper Restriction of Excessive Authentication Attempts",
        "owasp": "A04:2021-Insecure Design",
        "remediation": "Implement rate limiting and account lockout policies on sensitive endpoints (e.g. login, password reset, token generation).",
    },
    "web-waf-bypass": {
        "cwe": "CWE-693: Protection Mechanism Failure",
        "owasp": "A05:2021-Security Misconfiguration",
        "remediation": "Harden backend validation rather than relying entirely on edge WAF filtering rules. Ensure WAF inspection rules inspect encoded, commented, and polluted inputs.",
    },
    "web-file-upload": {
        "cwe": "CWE-434: Unrestricted Upload of File with Dangerous Type",
        "owasp": "A04:2021-Insecure Design",
        "remediation": "Validate file extensions and magic bytes against a strict allowlist. Store uploads outside the web root on isolated storage (e.g. S3) and serve with Content-Disposition: attachment.",
    },
    "web-ssl-tls": {
        "cwe": "CWE-326: Inadequate Encryption Strength",
        "owasp": "A02:2021-Cryptographic Failures",
        "remediation": "Disable legacy protocol versions (SSLv3, TLS 1.0, TLS 1.1) and deprecated ciphers (RC4, 3DES, CBC mode). Require TLS 1.2+ with modern AEAD cipher suites.",
    },
    "recon-whois": {
        "cwe": "CWE-200: Information Exposure",
        "owasp": "A05:2021-Security Misconfiguration",
        "remediation": "Enable domain privacy protection, DNSSEC, and ensure timely domain renewal.",
    },
    "recon-zonewalk": {
        "cwe": "CWE-200: Information Exposure",
        "owasp": "A05:2021-Security Misconfiguration",
        "remediation": "Use NSEC3 with opt-out to prevent DNS zone enumeration via NSEC walking.",
    },
    "recon-vhost": {
        "cwe": "CWE-200: Information Exposure",
        "owasp": "A05:2021-Security Misconfiguration",
        "remediation": "Configure the web server to reject requests with unknown Host headers. Use a default vhost that returns 403.",
    },
    "recon-email": {
        "cwe": "CWE-200: Information Exposure",
        "owasp": "A05:2021-Security Misconfiguration",
        "remediation": "Avoid publishing role-based and personal email addresses on public web pages. Use contact forms instead.",
    },
    "web-nosqli": {
        "cwe": "CWE-943: Improper Neutralization of Special Elements in Data Query Logic",
        "owasp": "A03:2021-Injection",
        "remediation": "Sanitize query selectors, cast input types explicitly (e.g. string/int), and use MongoDB schema validators or Mongoose with strict type checking to reject operator objects ($ne, $gt, $where).",
    },
    "web-ldapi": {
        "cwe": "CWE-90: LDAP Injection",
        "owasp": "A03:2021-Injection",
        "remediation": "Use LDAP filter encoding APIs to escape special characters (*, (, ), \\, NUL) before inserting untrusted values into search filters.",
    },
    "web-xpathi": {
        "cwe": "CWE-643: XPath Injection",
        "owasp": "A03:2021-Injection",
        "remediation": "Use parameterized XPath queries or pre-compiled XPath expressions with variable resolvers rather than string concatenation.",
    },
    "web-second-order": {
        "cwe": "CWE-74: Improper Neutralization of Special Elements in Output Used by a Downstream Component",
        "owasp": "A03:2021-Injection",
        "remediation": "Contextually encode all retrieved data before rendering in HTML, SQL, or command contexts, and re-validate data upon extraction from storage.",
    },
    "web-blind-cmdi": {
        "cwe": "CWE-78: OS Command Injection",
        "owasp": "A03:2021-Injection",
        "remediation": "Avoid invoking shell interpreters. Pass structured argument vectors to APIs like execve or subprocess without shell=True, and validate input against a strict allowlist.",
    },
    "web-bola": {
        "cwe": "CWE-639: Insecure Direct Object Reference",
        "owasp": "A01:2021-Broken Access Control",
        "remediation": "Enforce object-level authorization checks on every API request. Verify the requesting user is the owner of or authorized for the specific resource ID.",
    },
    "web-bfla": {
        "cwe": "CWE-285: Improper Authorization",
        "owasp": "A01:2021-Broken Access Control",
        "remediation": "Enforce role-based and function-level access control on all administrative and privileged endpoints and HTTP verbs (PUT, DELETE, PATCH).",
    },
    "web-mass-assignment": {
        "cwe": "CWE-915: Improperly Controlled Modification of Dynamically Determined Object Attributes",
        "owasp": "A04:2021-Insecure Design",
        "remediation": "Define strict Data Transfer Objects (DTOs) or use an allowlist of assignable model properties, discarding unauthorized fields (e.g. role, isAdmin).",
    },
    "web-excessive-data": {
        "cwe": "CWE-213: Exposure of Sensitive Information Due to Incompatible Policies",
        "owasp": "A01:2021-Broken Access Control",
        "remediation": "Filter API responses on the server side using response schemas or serializers. Never rely on the client to filter out sensitive object fields.",
    },
    "web-api-inventory": {
        "cwe": "CWE-1059: Incomplete Documentation",
        "owasp": "A09:2021-Security Logging and Monitoring Failures",
        "remediation": "Maintain an up-to-date API inventory, decommission deprecated and shadow endpoints, and restrict public access to API documentation and schemas in production.",
    },
    "web-http2": {
        "cwe": "CWE-400: Uncontrolled Resource Consumption",
        "owasp": "A04:2021-Insecure Design",
        "remediation": "Ensure web servers and reverse proxies are patched against HTTP/2 Rapid Reset (CVE-2023-44487) and enforce stream reset rate limits.",
    },
    "web-cors-preflight": {
        "cwe": "CWE-942: Overly Permissive CORS Policy",
        "owasp": "A01:2021-Broken Access Control",
        "remediation": "Avoid excessively long Access-Control-Max-Age values for dynamic origins, and do not reflect untrusted origins with credentials allowed in preflight responses.",
    },
    "web-dns-rebinding": {
        "cwe": "CWE-350: Reliance on Reverse DNS Resolution with a Security Boundary",
        "owasp": "A05:2021-Security Misconfiguration",
        "remediation": "Validate the Host header against a strict allowlist of domain names and reject requests with unrecognized or internal/loopback Host values.",
    },
    "web-cache-deception": {
        "cwe": "CWE-524: Use of Cache Containing Sensitive Information",
        "owasp": "A05:2021-Security Misconfiguration",
        "remediation": "Configure web cache servers to respect Cache-Control: no-store on authenticated dynamic pages and disallow caching based solely on URL path extensions.",
    },
    "web-business-logic": {
        "cwe": "CWE-840: Business Logic Errors",
        "owasp": "A04:2021-Insecure Design",
        "remediation": "Validate client IP addresses using secure reverse-proxy headers (reject spoofable headers like X-Forwarded-For if not set by a trusted proxy), and validate numeric business limits (positive quantities, non-zero prices).",
    },
    # Authentication & Session Security
    "web-session-fixation": {
        "cwe": "CWE-384: Session Fixation",
        "owasp": "A07:2021-Identification and Authentication Failures",
        "remediation": "Regenerate the session ID upon any authentication state change (login, logout, privilege escalation). Invalidate pre-authentication session tokens server-side.",
    },
    "web-login-bruteforce": {
        "cwe": "CWE-307: Improper Restriction of Excessive Authentication Attempts",
        "owasp": "A07:2021-Identification and Authentication Failures",
        "remediation": "Implement progressive delays, account lockout after a threshold, CAPTCHA challenges, and IP-based rate limiting on login endpoints.",
    },
    "web-password-policy": {
        "cwe": "CWE-521: Weak Password Requirements",
        "owasp": "A07:2021-Identification and Authentication Failures",
        "remediation": "Enforce a minimum password length of 8 characters with complexity requirements (mixed case, digits, special characters). Reject passwords found in common breach dictionaries.",
    },
    "web-session-entropy": {
        "cwe": "CWE-331: Insufficient Entropy",
        "owasp": "A07:2021-Identification and Authentication Failures",
        "remediation": "Generate session tokens using a cryptographically secure random number generator (e.g. secrets.token_hex or /dev/urandom) with at least 128 bits of entropy.",
    },
    "web-twofa-bypass": {
        "cwe": "CWE-308: Use of Single-factor Authentication",
        "owasp": "A07:2021-Identification and Authentication Failures",
        "remediation": "Enforce 2FA validation server-side before granting access to any authenticated resource. Do not expose post-auth redirect URLs before 2FA completion.",
    },
    "web-session-timeout": {
        "cwe": "CWE-613: Insufficient Session Expiration",
        "owasp": "A07:2021-Identification and Authentication Failures",
        "remediation": "Set session cookies with appropriate Max-Age or Expires values (e.g. 15-30 minutes for sensitive applications). Implement server-side idle session timeout.",
    },
    "web-concurrent-session": {
        "cwe": "CWE-613: Insufficient Session Expiration",
        "owasp": "A07:2021-Identification and Authentication Failures",
        "remediation": "Limit concurrent active sessions per user account. Invalidate previous sessions upon new login or provide users a way to review and terminate active sessions.",
    },
    "web-insecure-logout": {
        "cwe": "CWE-613: Insufficient Session Expiration",
        "owasp": "A07:2021-Identification and Authentication Failures",
        "remediation": "On logout, invalidate the session server-side and clear session cookies by setting them with an expired date and empty value. Ensure tokens cannot be replayed post-logout.",
    },
    "web-auth-bypass": {
        "cwe": "CWE-287: Improper Authentication",
        "owasp": "A07:2021-Identification and Authentication Failures",
        "remediation": "Enforce authentication checks on the canonical request path server-side. Do not rely on X-Original-URL, X-Rewrite-URL, or HTTP verb restrictions for access control.",
    },
    "web-token-leak": {
        "cwe": "CWE-598: Use of GET Request Method With Sensitive Query Strings",
        "owasp": "A07:2021-Identification and Authentication Failures",
        "remediation": "Never pass session tokens or credentials via URL query parameters. Set Referrer-Policy: no-referrer on pages with sensitive tokens and ensure Cache-Control: no-store on authenticated responses.",
    },

    # Advanced Web Application Security
    "web-csp-analysis": {
        "cwe": "CWE-693: Protection Mechanism Failure",
        "owasp": "A05:2021-Security Misconfiguration",
        "remediation": "Deploy a strict Content-Security-Policy: default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'. Avoid 'unsafe-inline' and 'unsafe-eval'.",
    },
    "web-cors-extended": {
        "cwe": "CWE-942: Overly Permissive CORS Policy",
        "owasp": "A01:2021-Broken Access Control",
        "remediation": "Validate Origin headers against a strict domain allowlist. Reject null origin, pre-domain, and post-domain origin variations. Never reflect arbitrary origins with credentials.",
    },
    "web-email-injection": {
        "cwe": "CWE-93: Improper Neutralization of CRLF Sequences in HTTP Headers",
        "owasp": "A03:2021-Injection",
        "remediation": "Sanitize all form inputs against newline characters (CR, LF) before passing to email sending functions. Use parameterized email APIs instead of raw SMTP header construction.",
    },
    "web-race-condition": {
        "cwe": "CWE-362: Concurrent Execution Using Shared Resource with Improper Synchronization",
        "owasp": "A04:2021-Insecure Design",
        "remediation": "Implement server-side mutex locks, database-level uniqueness constraints, or idempotency keys on state-changing operations to prevent time-of-check-to-time-of-use (TOCTOU) vulnerabilities.",
    },
    "web-graphql-injection": {
        "cwe": "CWE-400: Uncontrolled Resource Consumption",
        "owasp": "A04:2021-Insecure Design",
        "remediation": "Enforce query depth limits, complexity analysis, and field-level rate limiting on GraphQL endpoints. Disable field suggestions and batch queries in production.",
    },
    "web-security-txt": {
        "cwe": "CWE-1059: Incomplete Documentation",
        "owasp": "A09:2021-Security Logging and Monitoring Failures",
        "remediation": "Publish a valid security.txt file at /.well-known/security.txt per RFC 9116, including Contact, Expires, and optional Encryption and Policy fields.",
    },
}

DEFAULT_TAXONOMY = {
    "cwe": "CWE-200: Exposure of Sensitive Information",
    "owasp": "A05:2021-Security Misconfiguration",
    "remediation": "Review system configuration, validate inputs against strict schemas, and restrict access according to the principle of least privilege.",
}


def get_taxonomy(module_name: str) -> dict[str, str]:
    if not module_name:
        return DEFAULT_TAXONOMY.copy()

    # Direct match
    if module_name in TAXONOMY_MAP:
        return TAXONOMY_MAP[module_name].copy()

    # Prefix or fuzzy match (e.g., 'cve-*' or 'web-sqli-...')
    clean = module_name.lower().replace("_", "-")
    for key, data in TAXONOMY_MAP.items():
        if key in clean or clean in key:
            return data.copy()

    if clean.startswith("recon-cve-"):
        return {
            "cwe": "CWE-937: Using Components with Known Vulnerabilities",
            "owasp": "A06:2021-Vulnerable and Outdated Components",
            "remediation": "Upgrade the affected component or library to the vendor's latest patched release immediately.",
        }

    if clean.startswith("cve-"):
        return {
            "cwe": "CWE-937: Using Components with Known Vulnerabilities",
            "owasp": "A06:2021-Vulnerable and Outdated Components",
            "remediation": "Upgrade the affected component or library to the vendor's latest patched release immediately.",
        }

    return DEFAULT_TAXONOMY.copy()
