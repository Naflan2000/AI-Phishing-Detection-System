import re
import ipaddress
from urllib.parse import urlparse, parse_qs, unquote


SUSPICIOUS_WORDS = {
    "login", "signin", "verify", "verification", "secure", "security",
    "account", "update", "confirm", "confirmation", "password", "passwd",
    "credential", "wallet", "bank", "payment", "invoice", "billing",
    "unlock", "suspended", "alert", "recover", "reset", "authenticate",
    "authentication", "webscr", "bonus", "claim", "gift", "free"
}

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "buff.ly",
    "ow.ly", "shorturl.at", "cutt.ly", "rb.gy", "rebrand.ly"
}


def normalize_url(url):
    url = str(url).strip()

    if not url:
        return ""

    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url):
        url = "http://" + url

    return url


def extract_urls(text):
    if not text:
        return []

    pattern = r"""(?i)\b(?:(?:https?|ftp)://|www\.)[^\s<>"'()]+"""

    found = re.findall(pattern, text)

    cleaned = []

    for url in found:
        url = url.rstrip(".,;:!?)]}")

        if url not in cleaned:
            cleaned.append(url)

    return cleaned


def analyze_url(url):
    original = str(url).strip()
    normalized = normalize_url(original)

    if not normalized:
        return {
            "url": original,
            "risk_score": 0,
            "risk_level": "UNKNOWN",
            "signals": [],
            "features": {}
        }

    parsed = urlparse(normalized)

    hostname = (parsed.hostname or "").lower()
    path = parsed.path or ""
    query = parsed.query or ""
    full_url = unquote(normalized)

    signals = []
    score = 0

    # ---------------------------------------------------------
    # URL LENGTH
    # ---------------------------------------------------------

    url_length = len(normalized)

    if url_length >= 150:
        score += 15
        signals.append("Very long URL")

    elif url_length >= 100:
        score += 8
        signals.append("Long URL")

    # ---------------------------------------------------------
    # HTTPS
    # ---------------------------------------------------------

    uses_https = parsed.scheme.lower() == "https"

    if not uses_https:
        score += 15
        signals.append("Connection is not HTTPS")

    # ---------------------------------------------------------
    # IP ADDRESS
    # ---------------------------------------------------------

    ip_address = False

    try:
        ipaddress.ip_address(hostname)
        ip_address = True
        score += 25
        signals.append("URL uses an IP address instead of a domain")
    except ValueError:
        pass

    # ---------------------------------------------------------
    # DOMAIN STRUCTURE
    # ---------------------------------------------------------

    labels = [x for x in hostname.split(".") if x]

    num_dots = hostname.count(".")
    subdomain_level = max(len(labels) - 2, 0)

    if num_dots >= 5:
        score += 12
        signals.append("Excessive number of domain levels")

    elif num_dots >= 4:
        score += 6
        signals.append("Multiple domain levels")

    if subdomain_level >= 3:
        score += 12
        signals.append("Deep subdomain structure")

    # ---------------------------------------------------------
    # SUSPICIOUS CHARACTERS
    # ---------------------------------------------------------

    if "@" in normalized:
        score += 25
        signals.append("Contains @ symbol")

    num_dash = normalized.count("-")

    if num_dash >= 5:
        score += 10
        signals.append("Many hyphens detected")

    if "~" in normalized:
        score += 5
        signals.append("Contains tilde symbol")

    if "_" in normalized:
        score += 4
        signals.append("Contains underscore")

    if "%" in normalized:
        score += 4
        signals.append("Encoded characters detected")

    if "#" in normalized:
        score += 3
        signals.append("Fragment identifier detected")

    # ---------------------------------------------------------
    # QUERY PARAMETERS
    # ---------------------------------------------------------

    query_params = parse_qs(query)

    query_count = len(query_params)

    if query_count >= 8:
        score += 12
        signals.append("Large number of query parameters")

    elif query_count >= 5:
        score += 6
        signals.append("Multiple query parameters")

    # ---------------------------------------------------------
    # NUMERIC CHARACTERS
    # ---------------------------------------------------------

    numeric_count = sum(c.isdigit() for c in hostname)

    if numeric_count >= 8:
        score += 8
        signals.append("High number of numeric characters in hostname")

    # ---------------------------------------------------------
    # SUSPICIOUS WORDS
    # ---------------------------------------------------------

    lower_url = full_url.lower()

    detected_words = sorted(
        word for word in SUSPICIOUS_WORDS
        if word in lower_url
    )

    if detected_words:
        added = min(20, len(detected_words) * 4)
        score += added
        signals.append(
            "Suspicious security-related keywords: "
            + ", ".join(detected_words[:6])
        )

    # ---------------------------------------------------------
    # URL SHORTENER
    # ---------------------------------------------------------

    is_shortener = hostname in SHORTENERS

    if is_shortener:
        score += 15
        signals.append("Known URL-shortening service")

    # ---------------------------------------------------------
    # DOUBLE SLASH
    # ---------------------------------------------------------

    path_without_scheme = re.sub(
        r"^[a-zA-Z]+://",
        "",
        normalized
    )

    if "//" in path_without_scheme:
        score += 8
        signals.append("Unexpected double slash in URL path")

    # ---------------------------------------------------------
    # HOSTNAME SUSPICIOUS PATTERNS
    # ---------------------------------------------------------

    if re.search(r"(login|verify|secure|account).*(bank|paypal|microsoft|google|apple)",
                 hostname):
        score += 20
        signals.append("Possible brand impersonation pattern")

    # ---------------------------------------------------------
    # PERCENT ENCODING
    # ---------------------------------------------------------

    percent_count = normalized.count("%")

    if percent_count >= 5:
        score += 10
        signals.append("Heavy URL encoding")

    # ---------------------------------------------------------
    # RANDOM-LOOKING HOSTNAME
    # ---------------------------------------------------------

    if hostname:

        host_without_dots = hostname.replace(".", "")

        letters = sum(c.isalpha() for c in host_without_dots)
        digits = sum(c.isdigit() for c in host_without_dots)

        if len(host_without_dots) >= 15 and letters > 0:

            ratio = digits / max(len(host_without_dots), 1)

            if ratio > 0.35:
                score += 8
                signals.append("Unusual numeric/character pattern in hostname")

    # ---------------------------------------------------------
    # CAP SCORE
    # ---------------------------------------------------------

    score = min(score, 100)

    # ---------------------------------------------------------
    # RISK LEVEL
    # ---------------------------------------------------------

    if score >= 60:
        risk_level = "HIGH"

    elif score >= 35:
        risk_level = "MEDIUM"

    elif score >= 15:
        risk_level = "LOW"

    else:
        risk_level = "MINIMAL"

    # ---------------------------------------------------------
    # FEATURE SUMMARY
    # ---------------------------------------------------------

    features = {
        "UrlLength": url_length,
        "NumDots": num_dots,
        "SubdomainLevel": subdomain_level,
        "NumDash": num_dash,
        "AtSymbol": int("@" in normalized),
        "TildeSymbol": int("~" in normalized),
        "NumUnderscore": normalized.count("_"),
        "NumPercent": percent_count,
        "NumQueryComponents": query_count,
        "NumHash": normalized.count("#"),
        "NumNumericChars": numeric_count,
        "NoHttps": int(not uses_https),
        "IpAddress": int(ip_address),
        "HostnameLength": len(hostname),
        "PathLength": len(path),
        "QueryLength": len(query),
        "DoubleSlashInPath": int("//" in path_without_scheme),
        "NumSensitiveWords": len(detected_words),
        "Shortener": int(is_shortener)
    }

    return {
        "url": original,
        "risk_score": score,
        "risk_level": risk_level,
        "signals": signals,
        "features": features
    }


def analyze_text_urls(text):
    urls = extract_urls(text)

    results = [
        analyze_url(url)
        for url in urls
    ]

    if not results:
        return {
            "urls": [],
            "highest_risk": "NONE",
            "highest_score": 0,
            "total_urls": 0
        }

    highest = max(
        results,
        key=lambda x: x["risk_score"]
    )

    return {
        "urls": results,
        "highest_risk": highest["risk_level"],
        "highest_score": highest["risk_score"],
        "total_urls": len(results)
    }