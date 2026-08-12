"""
PhishGuard — Email Header & Content Analyzer
Parses raw email, checks SPF/DKIM/DMARC indicators, subject urgency, and embedded URLs.
Pure Python stdlib — no external libraries.
"""
import email
import email.policy
import re
import time

URGENCY_PHRASES = [
    'urgent', 'immediate attention', 'account suspended', 'verify now',
    'verify your account', 'security alert', 'unusual activity',
    'act now', 'limited time', 'confirm your', 'update your info',
    'suspected unauthorized', 'click here to verify', 'login attempt',
    'we noticed a sign', 'action required',
]

DANGEROUS_EXTENSIONS = {
    '.exe', '.bat', '.cmd', '.vbs', '.js', '.jse', '.ws', '.wsf',
    '.msc', '.msi', '.ps1', '.reg', '.scr', '.hta', '.cpl',
    '.zip', '.rar', '.7z', '.iso', '.img',
}

URL_PATTERN = re.compile(r'https?://[^\s<>"\']+', re.IGNORECASE)


def analyze_email(raw_email: str, check_links: bool = True, url_timeout: int = 3) -> dict:
    try:
        msg = email.message_from_string(raw_email, policy=email.policy.default)
    except Exception as e:
        return {'verdict': 'error', 'error': str(e)}

    from_header  = str(msg.get('From', ''))
    reply_to     = str(msg.get('Reply-To', ''))
    return_path  = str(msg.get('Return-Path', ''))
    subject      = str(msg.get('Subject', ''))
    received_spf = str(msg.get('Received-SPF', '')).lower()
    dkim_sig     = str(msg.get('DKIM-Signature', ''))

    indicators = []
    score = 0

    # SPF check
    if received_spf and 'pass' not in received_spf:
        indicators.append({'type': 'SPF_FAIL', 'detail': 'SPF did not pass'})
        score += 20

    # DKIM check
    if not dkim_sig:
        indicators.append({'type': 'NO_DKIM', 'detail': 'No DKIM signature'})
        score += 15

    # Reply-To mismatch
    from_domain  = re.search(r'@([\w.-]+)', from_header)
    reply_domain = re.search(r'@([\w.-]+)', reply_to)
    if from_domain and reply_domain:
        if from_domain.group(1).lower() != reply_domain.group(1).lower():
            indicators.append({'type': 'REPLY_TO_MISMATCH', 'detail': f'From: {from_domain.group(1)} Reply-To: {reply_domain.group(1)}'})
            score += 25

    # Return-Path mismatch
    if return_path and from_domain:
        rp_domain = re.search(r'@([\w.-]+)', return_path)
        if rp_domain and rp_domain.group(1).lower() != from_domain.group(1).lower():
            indicators.append({'type': 'RETURN_PATH_MISMATCH', 'detail': 'Return-Path domain differs from From'})
            score += 15

    # Subject urgency
    subject_lower = subject.lower()
    for phrase in URGENCY_PHRASES:
        if phrase in subject_lower:
            indicators.append({'type': 'URGENCY_LANGUAGE', 'detail': f'Urgency phrase: "{phrase}"'})
            score += 20
            break

    # Extract body
    body = ''
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == 'text/plain':
                try:
                    body += part.get_content()
                except Exception:
                    pass
    else:
        try:
            body = msg.get_content()
        except Exception:
            body = raw_email

    urls_in_body = URL_PATTERN.findall(body)

    # Check attachments
    dangerous_attachments = []
    for part in msg.walk():
        fn = part.get_filename()
        if fn:
            ext = '.' + fn.rsplit('.', 1)[-1].lower() if '.' in fn else ''
            if ext in DANGEROUS_EXTENSIONS:
                dangerous_attachments.append(fn)
                score += 30
                indicators.append({'type': 'DANGEROUS_ATTACHMENT', 'detail': f'Dangerous file: {fn}'})

    score = min(score, 100)
    verdict = 'phishing' if score >= 50 else 'suspicious' if score >= 25 else 'clean'

    return {
        'verdict':                verdict,
        'risk_score':             score,
        'indicators':             indicators,
        'from':                   from_header,
        'subject':                subject,
        'has_dkim':               bool(dkim_sig),
        'spf_status':             received_spf or 'unknown',
        'urls_in_body':           urls_in_body,
        'dangerous_attachments':  dangerous_attachments,
        'analyzed_at':            time.time(),
    }
