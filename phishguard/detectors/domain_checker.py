"""
PhishGuard — Domain Typosquatting & Homograph Detector
Checks if a domain is a lookalike of a known legitimate domain.
Pure Python stdlib — no external libraries.
"""
import unicodedata
import re

PROTECTED_DOMAINS = [
    'paypal.com', 'apple.com', 'google.com', 'amazon.com',
    'microsoft.com', 'netflix.com', 'facebook.com', 'instagram.com',
    'twitter.com', 'linkedin.com', 'dropbox.com', 'icloud.com',
    'chase.com', 'wellsfargo.com', 'adobe.com', 'zoom.us',
    'discord.com', 'ebay.com', 'walmart.com', 'citibank.com',
    'bankofamerica.com', 'usps.com', 'airbnb.com', 'spotify.com',
    'slack.com', 'steampowered.com', 'wellsfargo.com',
]


def levenshtein(s1: str, s2: str) -> int:
    if len(s1) < len(s2):
        return levenshtein(s2, s1)
    if len(s2) == 0:
        return len(s1)
    prev_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        curr_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions    = prev_row[j + 1] + 1
            deletions     = curr_row[j] + 1
            substitutions = prev_row[j] + (c1 != c2)
            curr_row.append(min(insertions, deletions, substitutions))
        prev_row = curr_row
    return prev_row[-1]


def normalize_domain(domain: str) -> str:
    """Normalize Unicode homoglyphs to ASCII equivalents."""
    try:
        normalized = unicodedata.normalize('NFKD', domain)
        return normalized.encode('ascii', 'ignore').decode().lower()
    except Exception:
        return domain.lower()


def check_domain(domain: str) -> dict:
    domain = domain.lower().strip().replace('http://', '').replace('https://', '')
    normalized = normalize_domain(domain)

    matches = []
    for protected in PROTECTED_DOMAINS:
        prot_parts = protected.split('.')
        dom_parts  = normalized.split('.')
        prot_root  = prot_parts[0]
        dom_root   = dom_parts[0] if dom_parts else ''
        distance   = levenshtein(prot_root, dom_root)

        if distance == 0 and domain == protected:
            return {'domain': domain, 'is_protected': True, 'matches': [], 'verdict': 'legitimate'}

        if 0 < distance <= 2 and len(prot_root) > 4:
            similarity = 1.0 - (distance / max(len(prot_root), len(dom_root)))
            matches.append({
                'target':        protected,
                'edit_distance': distance,
                'similarity':    round(similarity, 2),
                'confidence':    'high' if distance == 1 else 'medium',
            })

    # Check if a protected brand appears in subdomain
    dom_parts = normalized.split('.')
    for protected in PROTECTED_DOMAINS:
        prot_name = protected.split('.')[0]
        if len(dom_parts) > 2 and prot_name in '.'.join(dom_parts[:-2]):
            matches.append({
                'target':        protected,
                'edit_distance': 0,
                'similarity':    1.0,
                'confidence':    'high',
                'reason':        'Brand in subdomain',
            })
            break

    verdict = 'typosquatting' if matches else 'clean'
    return {
        'domain':        domain,
        'normalized':    normalized,
        'matches':       matches,
        'verdict':       verdict,
        'is_suspicious': bool(matches),
    }
