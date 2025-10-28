// script.js
// Client-side heuristics and call to backend for a fuller check.

const checkBtn = document.getElementById('checkBtn');
const urlInput = document.getElementById('urlInput');
const resultBox = document.getElementById('result');

function showResult(score, reasons) {
  resultBox.className = 'result';
  if (score >= 70) resultBox.classList.add('high');
  else if (score >= 35) resultBox.classList.add('medium');
  else resultBox.classList.add('low');

  resultBox.innerHTML = `<strong>Risk score:</strong> ${score}/100<br><strong>Reasons:</strong><ul>${reasons.map(r=>`<li>${r}</li>`).join('')}</ul>`;
}

function clientHeuristics(url) {
  const reasons = [];
  let score = 0;

  try {
    const u = new URL(url);
    const hostname = u.hostname.toLowerCase();

    // HTTP vs HTTPS
    if (u.protocol === 'http:') { score += 15; reasons.push('Uses plain HTTP (not HTTPS) — often flagged.'); }

    // IP address instead of domain
    if (/^\d+\.\d+\.\d+\.\d+$/.test(hostname)) { score += 20; reasons.push('Direct IP address used — sometimes flagged.'); }

    // Uncommon TLDs
    if (/\.(zip|review|top|click|work|party|gq|icu|men)$/.test(hostname)) { score += 10; reasons.push('TLD often used by disposable sites/short-lived domains.'); }

    // Shortener domains
    const shorteners = ['bit.ly','tinyurl.com','t.co','ow.ly','is.gd','buff.ly','goo.gl'];
    if (shorteners.includes(hostname)) { score += 25; reasons.push('URL shortener detected — many filters block shorteners.'); }

    // Suspicious keywords in hostname or path
    const suspicious = ['proxy','vpn','unblock','bypass','anonymizer','torrent','warez','crack','adult','porn','gaming','cheat'];
    const joined = (hostname + u.pathname + u.search).toLowerCase();
    suspicious.forEach(k => { if (joined.includes(k)) { score += 18; reasons.push(`Contains keyword "${k}" associated with blocked content.`); }});

    // Long URL (may indicate tracking or redirect chains)
    if (url.length > 120) { score += 6; reasons.push('Very long URL — could include redirect params.'); }

    // Non-standard port
    if (u.port && u.port !== '80' && u.port !== '443') { score += 10; reasons.push(`Uses non-standard port ${u.port}.`); }
  } catch (e) {
    reasons.push('Invalid URL format.');
    score = 100;
  }

  // clamp
  if (score > 100) score = 100;
  return {score, reasons};
}

async function checkServer(url) {
  // call backend for extended heuristics
  try {
    const resp = await fetch('http://localhost:5000/analyze', {
      method: 'POST',
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify({url})
    });
    if (!resp.ok) throw new Error('Server returned error');
    const data = await resp.json();
    return data;
  } catch (e) {
    return {score: 0, reasons: ['Backend not available — running client-only heuristics.']};
  }
}

checkBtn.addEventListener('click', async () => {
  const url = urlInput.value.trim();
  if (!url) { resultBox.innerHTML = 'Please paste a URL.'; return; }

  // Do client-side checks first:
  const client = clientHeuristics(url);

  // Try backend (if running). Merge results (simple average)
  const backend = await checkServer(url);
  let finalScore = Math.round((client.score + (backend && backend.score ? backend.score : 0)) / (backend && backend.score ? 2 : 1));
  const reasons = [...new Set([...(client.reasons||[]), ...(backend.reasons||[])])];

  showResult(finalScore, reasons);

  // safety reminder
  reasons.push('Reminder: This tool does not aid in bypassing filters.');
});
