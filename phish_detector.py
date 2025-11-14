#!/usr/bin/env python3
import sys, re, email
from urllib.parse import urlparse
import tldextract

SUSPICIOUS_TLDS = {'.xyz', '.top', '.club', '.info'}

def extract_urls(text):
    return re.findall(r'https?://[^\s'"<>]+', text or '')

def is_ip_link(url):
    host = urlparse(url).netloc
    return bool(re.match(r'^\d+\.\d+\.\d+\.\d+$', host))

def check_anchor_mismatch(html):
    a_rx = re.compile(r'<a\s+[^>]*href=["\'](?P<h>[^"\']+)["\'][^>]*>(?P<t>.*?)</a>', re.I|re.S)
    mism = []
    for m in a_rx.finditer(html or ''):
        href = m.group('h')
        text = re.sub(r'<.*?>','', m.group('t')).strip()
        if '.' in text and domain_of(href) and text not in domain_of(href):
            mism.append((text, href))
    return mism

def domain_of(url):
    return urlparse(url).netloc.lower()

def score_message(msg):
    body = ''
    html = ''
    if msg.is_multipart():
        for p in msg.walk():
            c = p.get_content_type()
            if c == 'text/plain':
                body += p.get_payload(decode=True).decode(errors='ignore')
            elif c == 'text/html':
                html += p.get_payload(decode=True).decode(errors='ignore')
    else:
        body = msg.get_payload(decode=True).decode(errors='ignore')
    urls = extract_urls(html + '\n' + body)
    score = 0
    findings = []
    for u in urls:
        if is_ip_link(u):
            score += 3
            findings.append(f'IP link: {u}')
        ext = tldextract.extract(u)
        tld = '.' + ext.suffix if ext.suffix else ''
        if tld in SUSPICIOUS_TLDS:
            score += 2
            findings.append(f'Suspicious TLD: {u}')
    mism = check_anchor_mismatch(html)
    if mism:
        score += 4
        findings.append(f'Anchor mismatch: {mism}')
    for p in msg.walk():
        if p.get_content_maintype() != 'multipart' and p.get('Content-Disposition'):
            fn = p.get_filename()
            if fn:
                score += 2
                findings.append(f'Attachment: {fn}')
    if score >= 6:
        level = 'High'
    elif score >=3:
        level = 'Medium'
    else:
        level = 'Low'
    return {'score': score, 'level': level, 'urls': urls, 'findings': findings}

def analyze(path):
    with open(path, 'rb') as f:
        msg = email.message_from_bytes(f.read())
    hdr = {'from': msg.get('From'), 'to': msg.get('To'), 'subject': msg.get('Subject'), 'date': msg.get('Date')}
    res = score_message(msg)
    return hdr, res

def main():
    if len(sys.argv) < 2:
        print('Usage: python phish_detector.py <email.eml>')
        sys.exit(1)
    hdr, res = analyze(sys.argv[1])
    print('Email:', hdr)
    print('Risk score:', res['score'], 'Level:', res['level'])
    print('URLs found:')
    for u in res['urls']:
        print(' -', u)
    print('Findings:')
    for f in res['findings']:
        print(' -', f)

if __name__ == '__main__':
    main()
