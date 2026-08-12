"""
PhishGuard — URL Phishing Analyzer
Pure Python stdlib — no external ML libraries.
Uses heuristic scoring: each rule contributes a weighted risk score.
"""
import re
import urllib.parse
import urllib.request
import urllib.error
import socket
import time

RISK_WEIGHTS = {
    'ip_address_host':          25,
    'excessive_subdomains':     15,
    'suspicious_tld':           20,
    'long_url':                 10,
    'url_shortener':            20,
    'login_keyword':            10,
    'credential_keyword':       15,
    'brand_in_subdomain':       25,
    'misleading_path':          15,
    'punycode_domain':          20,
    'excessive_dots':           10,
    'non_standard_port':        15,
    'http_not_https':           10,
    'double_slash_redirect':    20,
    'at_symbol':                30,
    'hex_encoding':             15,
    'long_subdomain':           10,
    'excessive_hyphens':        10,
    'suspicious_query_param':   10,
}

SUSPICIOUS_TLDS = {
    '.tk', '.ml', '.ga', '.cf', '.gw', '.xyz', '.top', '.club',
    '.work', '.click', '.link', '.surf', '.website', '.online',
    '.site', '.tech', '.icu', '.live', '.fun',
}

URL_SHORTENERS = {
    'bit.ly', 'tinyurl.com', 't.me', 'shrten.com', 'owl.ly',
    'goo.gl', 'is.gd', 'buff.ly', 'lntr.in', 'p.ni', 'y.u',
}

PROTECTED_BRANDS = {
    'paypal', 'apple', 'google', 'amazon', 'microsoft', 'netflix',
    'facebook', 'instagram', 'twitter', 'linkedin', 'dropbox',
    'appleid', 'icloud', 'chase', 'adobe', 'zoom', 'discord',
    'steam', 'ebay', 'walmart', 'citibank', 'bankofamerica',
    'wellsfargo',
}

CREDENTIAL_KEYWORDS = {
    'password', 'passwd', 'ssn', 'cvv', 'ccn', 'cardno',
    'accountnumber', 'accountno', 'pinnumber',
}

LOGIN_KEYWORDS = {
    'login', 'signin', 'secure', 'verify', 'verification',
    'confirm', 'update', 'update-account', 'account-verify',
}


def _get_score_verdict(score: int) -> str:
    if score >= 60: return 'phishing'
    if score >= 35: return 'suspicious'
    if score >= 15: return 'low_risk'
    return 'clean'


def _get_confidence(score: int, indicator_count: int) -> str:
    if score >= 75 or indicator_count >= 4: return 'high'
    if score >= 40 or indicator_count >= 2: return 'medium'
    return 'low'


def analyze_url(url: str, deep_inspect: bool = False, fetch_timeout: int = 5) -> dict:
    indicators = []
    score = 0

    try:
        parsed = urllib.parse.urlparse(url)
    except Exception:
        return {'url': url, 'verdict': 'error', 'risk_score': 0, 'indicators': [], 'error': 'Unparseable URL'}

    host   = parsed.hostname or ''
    path   = parsed.path or ''
    query  = parsed.query or ''
    scheme = parsed.scheme or ''
    port   = parsed.port
    parts  = host.split('.')

    # Rule 1: IP address host
    if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', host):
        w = RISK_WEIGHTS['ip_address_host']
        indicators.append({'rule': 'ip_address_host', 'weight': w, 'detail': f'Host is raw IP: {host}'})
        score += w

    # Rule 2: excessive subdomains
    if len(parts) > 4:
        w = RISK_WEIGHTS['excessive_subdomains']
        indicators.append({'rule': 'excessive_subdomains', 'weight': w, 'detail': f'{len(parts)} subdomain levels'})
        score += w

    # Rule 3: suspicious TLD
    tld = '.' + parts[-1] if parts else ''
    if tld in SUSPICIOUS_TLDS:
        w = RISK_WEIGHTS['suspicious_tld']
        indicators.append({'rule': 'suspicious_tld', 'weight': w, 'detail': f'Suspicious TLD: {tld}'})
        score += w

    # Rule 4: long URL
    if len(url) > 100:
        w = RISK_WEIGHTS['long_url']
        indicators.append({'rule': 'long_url', 'weight': w, 'detail': f'URL length {len(url)} chars'})
        score += w

    # Rule 5: URL shortener
    if host in URL_SHORTENERS:
        w = RISK_WEIGHTS['url_shortener']
        indicators.append({'rule': 'url_shortener', 'weight': w, 'detail': f'Known URL shortener: {host}'})
        score += w

    # Rule 6: login keyword in path/query
    url_lower = url.lower()
    for kw in LOGIN_KEYWORDS:
        if kw in url_lower:
            w = RISK_WEIGHTS['login_keyword']
            indicators.append({'rule': 'login_keyword', 'weight': w, 'detail': f'Keyword "{kw}" in URL'})
            score += w
            break

    # Rule 7: credential keyword in query
    query_lower = query.lower()
    for kw in CREDENTIAL_KEYWORDS:
        if kw in query_lower:
            w = RISK_WEIGHTS['credential_keyword']
            indicators.append({'rule': 'credential_keyword', 'weight': w, 'detail': f'Sensitive keyword "{kw}" in query'})
            score += w
            break

    # Rule 8: brand in subdomain
    if len(parts) > 2:
        subdomain = '.'.join(parts[:-2]).lower()
        for brand in PROTECTED_BRANDS:
            if brand in subdomain:
                w = RISK_WEIGHTS['brand_in_subdomain']
                indicators.append({'rule': 'brand_in_subdomain', 'weight': w, 'detail': f'Brand "{brand}" in subdomain'})
                score += w
                break

    # Rule 9: brand in path but not in host
    path_lower = path.lower()
    host_lower = host.lower()
    for brand in PROTECTED_BRANDS:
        if brand in path_lower and brand not in host_lower:
            w = RISK_WEIGHTS['misleading_path']
            indicators.append({'rule': 'misleading_path', 'weight': w, 'detail': f'Brand "{brand}" in path but not host'})
            score += w
            break

    # Rule 10: punycode domain (IDN homograph)
    if 'xn--' in host:
        w = RISK_WEIGHTS['punycode_domain']
        indicators.append({'rule': 'punycode_domain', 'weight': w, 'detail': 'IDN punycode domain (homograph attack)'})
        score += w

    # Rule 11: excessive dots
    dot_count = url.count('.')
    if dot_count > 6:
        w = RISK_WEIGHTS['excessive_dots']
        indicators.append({'rule': 'excessive_dots', 'weight': w, 'detail': f'{dot_count} dots in URL'})
        score += w

    # Rule 12: non-standard port
    if port and port not in (80, 443, 8008, 8080):
        w = RISK_WEIGHTS['non_standard_port']
        indicators.append({'rule': 'non_standard_port', 'weight': w, 'detail': f'Non-standard port: {port}'})
        score += w

    # Rule 13: HTTP not HTTPS
    if scheme == 'http':
        w = RISK_WEIGHTS['http_not_https']
        indicators.append({'rule': 'http_not_https', 'weight': w, 'detail': 'Unencrypted HTTP connection'})
        score += w

    # Rule 14: double slash redirect in path
    if '//' in path:
        w = RISK_WEIGHTS['double_slash_redirect']
        indicators.append({'rule': 'double_slash_redirect', 'weight': w, 'detail': 'Double slash redirect in path'})
        score += w

    # Rule 15: @ symbol in URL
    if '@' in url:
        w = RISK_WEIGHTS['at_symbol']
        indicators.append({'rule': 'at_symbol', 'weight': w, 'detail': '@ symbol hides real host'})
        score += w

    # Rule 16: excessive hex encoding
    hex_matches = re.findall(r'%[89a-fA-F][0-9a-fA-F]', url)
    if len(hex_matches) >= 3:
        w = RISK_WEIGHTS['hex_encoding']
        indicators.append({'rule': 'hex_encoding', 'weight': w, 'detail': f'{len(hex_matches)} hex-encoded chars'})
        score += w

    # Rule 17: long subdomain (DGA indicator)
    if len(parts) > 2:
        sub = parts[0]
        if len(sub) > 30:
            w = RISK_WEIGHTS['long_subdomain']
            indicators.append({'rule': 'long_subdomain', 'weight': w, 'detail': f'Subdomain length {len(sub)} (may be DGA)'})
            score += w

    # Rule 18: excessive hyphens in host
    hyphen_count = host.count('-')
    if hyphen_count > 3:
        w = RISK_WEIGHTS['excessive_hyphens']
        indicators.append({'rule': 'excessive_hyphens', 'weight': w, 'detail': f'{hyphen_count} hyphens in host'})
        score += w

    score = min(score, 100)
    verdict    = _get_score_verdict(score)
    confidence = _get_confidence(score, len(indicators))

    result = {
        'url':          url,
        'host':         host,
        'scheme':       scheme,
        'risk_score':   score,
        'verdict':      verdict,
        'confidence':   confidence,
        'indicators':   indicators,
        'rules_fired':  len(indicators),
        'analyzed_at':  time.time(),
    }

    if deep_inspect:
        result['deep_inspect'] = _deep_inspect(url, fetch_timeout)

    return result


def _deep_inspect(url: str, timeout: int = 5) -> dict:
    """Fetch URL and check final destination and redirect chain."""
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            final_url = resp.url
            status = resp.status
            return {'reachable': True, 'final_url': final_url, 'status_code': status, 'redirected': final_url != url}
    except urllib.error.HTTPError as e:
        return {'reachable': True, 'status_code': e.code, 'error': str(e)}
    except (urllib.error.URLError, socket.timeout, Exception) as e:
        return {'reachable': False, 'error': str(e)}
