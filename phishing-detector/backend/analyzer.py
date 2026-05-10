import re
import urllib.parse
from typing import List, Dict, Any

PHISHING_KEYWORDS = [
    'verify your account', 'confirm your identity', 'update your payment',
    'your account has been suspended', 'click here immediately', 'act now',
    'limited time offer', 'you have been selected', 'claim your prize',
    'your account will be closed', 'unusual activity detected', 'security alert',
    'reset your password immediately', 'login attempt', 'verify now',
    'congratulations you won', 'free gift', 'you are a winner',
    'bank account', 'social security', 'wire transfer', 'western union',
    'nigerian prince', 'inheritance funds', 'lottery winner',
    'kindly', 'dear customer', 'dear user', 'dear valued member',
    'your paypal', 'your amazon', 'your apple id', 'your netflix',
]

URGENCY_PHRASES = [
    'urgent', 'immediately', 'expires today', 'within 24 hours',
    'act fast', 'last chance', 'final warning', 'account suspended',
    'respond now', 'do not ignore', 'important notice', 'action required',
    'time sensitive', 'expires soon', 'final notice',
]

SUSPICIOUS_DOMAINS = [
    'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'short.link',
    'rb.gy', 'cutt.ly', 'shorturl.at', 'is.gd', 'tiny.cc',
]

LEGIT_DOMAINS = [
    'gmail.com', 'yahoo.com', 'outlook.com', 'hotmail.com', 'icloud.com',
    'microsoft.com', 'apple.com', 'google.com', 'amazon.com', 'paypal.com',
    'facebook.com', 'twitter.com', 'linkedin.com', 'github.com',
]

SUSPICIOUS_TLDS = ['.xyz', '.top', '.click', '.loan', '.work', '.gq', '.ml', '.cf', '.tk', '.ga']


def extract_urls(text: str) -> List[str]:
    pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
    return re.findall(pattern, text)


def extract_sender_domain(sender: str) -> str:
    match = re.search(r'@([\w.\-]+)', sender)
    return match.group(1).lower() if match else ''


def check_urls(urls: List[str]) -> Dict[str, Any]:
    findings = []
    score = 0
    for url in urls:
        parsed = urllib.parse.urlparse(url)
        domain = parsed.netloc.lower()

        if any(d in domain for d in SUSPICIOUS_DOMAINS):
            findings.append({'url': url, 'reason': 'URL shortener detected', 'severity': 'high'})
            score += 25

        if re.match(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', domain):
            findings.append({'url': url, 'reason': 'IP address used instead of domain', 'severity': 'high'})
            score += 30

        if any(url.lower().endswith(tld) or f'{tld}/' in url.lower() for tld in SUSPICIOUS_TLDS):
            findings.append({'url': url, 'reason': 'Suspicious TLD detected', 'severity': 'medium'})
            score += 15

        if domain.count('-') > 2:
            findings.append({'url': url, 'reason': 'Excessive hyphens in domain name', 'severity': 'medium'})
            score += 10

        for legit in LEGIT_DOMAINS:
            brand = legit.split('.')[0]
            if brand in domain and legit not in domain:
                findings.append({'url': url, 'reason': f'Possible brand impersonation of {legit}', 'severity': 'high'})
                score += 35
                break

        if len(domain) > 40:
            findings.append({'url': url, 'reason': 'Unusually long domain name', 'severity': 'low'})
            score += 5

    return {'findings': findings, 'score': min(score, 100)}


def check_sender(sender: str) -> Dict[str, Any]:
    findings = []
    score = 0
    if not sender:
        return {'findings': findings, 'score': score}

    domain = extract_sender_domain(sender)

    display_name_match = re.match(r'^"?([^<"]+)"?\s*<', sender)
    if display_name_match:
        display_name = display_name_match.group(1).lower()
        for legit in LEGIT_DOMAINS:
            brand = legit.split('.')[0]
            if brand in display_name and domain and legit not in domain:
                findings.append({'reason': f'Display name claims to be {brand} but email is from {domain}', 'severity': 'high'})
                score += 40

    if domain:
        for tld in SUSPICIOUS_TLDS:
            if domain.endswith(tld):
                findings.append({'reason': f'Sender uses suspicious TLD: {tld}', 'severity': 'high'})
                score += 25

        if re.match(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', domain):
            findings.append({'reason': 'Sender uses IP address instead of domain', 'severity': 'high'})
            score += 35

        for legit in LEGIT_DOMAINS:
            brand = legit.split('.')[0]
            if brand in domain and legit not in domain:
                findings.append({'reason': f'Domain appears to impersonate {legit}', 'severity': 'high'})
                score += 40
                break

        if domain.count('-') > 2:
            findings.append({'reason': 'Excessive hyphens in sender domain', 'severity': 'medium'})
            score += 10

    return {'findings': findings, 'score': min(score, 100)}


def check_content(subject: str, body: str) -> Dict[str, Any]:
    findings = []
    score = 0
    combined = (subject + ' ' + body).lower()

    matched_keywords = [kw for kw in PHISHING_KEYWORDS if kw in combined]
    if matched_keywords:
        count = len(matched_keywords)
        findings.append({
            'reason': f'Phishing keyword(s) detected: {", ".join(matched_keywords[:3])}{"..." if count > 3 else ""}',
            'severity': 'high' if count >= 3 else 'medium'
        })
        score += min(count * 8, 40)

    matched_urgency = [p for p in URGENCY_PHRASES if p in combined]
    if matched_urgency:
        findings.append({
            'reason': f'Urgency language detected: {", ".join(matched_urgency[:3])}',
            'severity': 'medium'
        })
        score += min(len(matched_urgency) * 6, 25)

    if body:
        upper_ratio = sum(1 for c in body if c.isupper()) / max(len(body), 1)
        if upper_ratio > 0.3 and len(body) > 50:
            findings.append({'reason': 'Excessive capitalization in email body', 'severity': 'low'})
            score += 10

        exclamation_count = body.count('!')
        if exclamation_count > 3:
            findings.append({'reason': f'Excessive use of exclamation marks ({exclamation_count})', 'severity': 'low'})
            score += 5

        if re.search(r'(password|ssn|credit card|bank account|account number).{0,30}(below|here|above|attached)', combined):
            findings.append({'reason': 'Request for sensitive information detected', 'severity': 'high'})
            score += 30

        if re.search(r'\$[\d,]+', body) or re.search(r'[\d,]+ dollars', combined):
            findings.append({'reason': 'Monetary amounts mentioned', 'severity': 'low'})
            score += 5

    return {'findings': findings, 'score': min(score, 100)}


def analyze_email(sender: str, subject: str, body: str) -> Dict[str, Any]:
    urls = extract_urls(body + ' ' + subject)
    url_analysis = check_urls(urls)
    sender_analysis = check_sender(sender)
    content_analysis = check_content(subject, body)

    raw_score = (
        url_analysis['score'] * 0.35 +
        sender_analysis['score'] * 0.35 +
        content_analysis['score'] * 0.30
    )
    risk_score = min(round(raw_score), 100)

    high_findings = [f for f in (url_analysis['findings'] + sender_analysis['findings'] + content_analysis['findings']) if f.get('severity') == 'high']
    if len(high_findings) >= 2 and risk_score < 65:
        risk_score = min(risk_score + 15, 100)

    if risk_score >= 65:
        verdict = 'phishing'
        verdict_label = 'Phishing Detected'
    elif risk_score >= 35:
        verdict = 'suspicious'
        verdict_label = 'Suspicious'
    else:
        verdict = 'safe'
        verdict_label = 'Likely Safe'

    all_findings = (
        [dict(f, category='URL') for f in url_analysis['findings']] +
        [dict(f, category='Sender') for f in sender_analysis['findings']] +
        [dict(f, category='Content') for f in content_analysis['findings']]
    )

    all_findings.sort(key=lambda x: {'high': 0, 'medium': 1, 'low': 2}.get(x.get('severity', 'low'), 3))

    return {
        'verdict': verdict,
        'verdict_label': verdict_label,
        'risk_score': risk_score,
        'urls_found': urls,
        'url_score': url_analysis['score'],
        'sender_score': sender_analysis['score'],
        'content_score': content_analysis['score'],
        'findings': all_findings,
        'sender': sender,
        'subject': subject,
    }
