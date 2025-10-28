# server.py
# Simple Flask API to perform additional heuristic checks server-side.
# pip install flask

from flask import Flask, request, jsonify
from urllib.parse import urlparse
import re

app = Flask(__name__)

SHORTENERS = {
    'bit.ly','tinyurl.com','t.co','ow.ly','is.gd','buff.ly','goo.gl','rebrand.ly','short.ly'
}

SUSPICIOUS_KEYWORDS = [
    'proxy','vpn','unblock','bypass','anonymizer','torrent','warez','crack','cheat','porn','adult','sex','gamble','gaming','stream','movie','watch'
]

COMMON_BLOCKED_CATEGORIES = {
    'proxy/vpn': ['proxy','vpn','anonymizer','unblock'],
    'adult': ['porn','adult','sex'],
    'gaming': ['gaming','cheat'],
    'streaming': ['stream','watch','movie']
}

def analyze_url(u):
    reasons = []
    score = 0

    try:
        p = urlparse(u)
        hostname = (p.hostname or '').lower()
        path = (p.path or '') + (p.query or '')

        # invalid or missing scheme
        if p.scheme not in ('http','https'):
            reasons.append('Unusual or missing URL scheme.')
            score += 20

        # shorteners
        if hostname in SHORTENERS:
            reasons.append('URL shortener detected (commonly blocked).')
            score += 30

        # ip address in hostname
        if re.match(r'^\d+\.\d+\.\d+\.\d+$', hostname):
            reasons.append('Direct IP address used.')
            score += 20

        # suspicious keywords
        for k in SUSPICIOUS_KEYWORDS:
            if k in hostname or k in path.lower():
                reasons.append(f'Keyword "{k}" present in domain/path.')
                score += 20

        # uncommon TLDs heuristic
        if re.search(r'\.(zip|review|top|click|work|party|icu|men)(?:$|/)', hostname):
            reasons.append('Uncommon TLD associated with disposable sites.')
            score += 10

        # port check
        if p.port and p.port not in (80,443):
            reasons.append(f'Nonstandard port used: {p.port}')
            score += 10

        # length
        if len(u) > 180:
            reasons.append('Very long URL; may include redirect/tracking tokens.')
            score += 6

    except Exception as e:
        reasons.append('Error parsing URL.')
        score = 100

    # clamp
    if score > 100: score = 100
    return score, reasons

@app.route('/analyze', methods=['POST'])
def analyze():
    data = request.get_json(force=True)
    url = data.get('url','').strip()
    if not url:
        return jsonify({'score':100, 'reasons':['No URL provided.']}), 400

    # simple defensive restriction: don't fetch or probe sites.
    score, reasons = analyze_url(url)

    # Add a small modifier based on category matches (example)
    # (We're not contacting any external categorization service here.)
    for cat, terms in COMMON_BLOCKED_CATEGORIES.items():
        for t in terms:
            if t in (url.lower()):
                reasons.append(f'Category hint: {cat}')
                score += 8

    if score > 100: score = 100

    return jsonify({'score': score, 'reasons': reasons})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
