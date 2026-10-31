"""
Optional Flask Web Interface for the Password Strength Analyzer.
Run with: `python app.py` and open http://127.0.0.1:5000 in your browser.
"""

from flask import Flask, request, jsonify, render_template_string
from src.analyzer import PasswordAnalyzer
from src.generator import PasswordGenerator
from src.database import PasswordHistoryDB

app = Flask(__name__)
db = PasswordHistoryDB("password_history.db")

HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Password Strength Analyzer & Crypto Guard</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        :root {
            --bg: #0f172a;
            --card: #1e293b;
            --text: #f8fafc;
            --muted: #94a3b8;
            --accent: #38bdf8;
            --danger: #ef4444;
            --warn: #f59e0b;
            --success: #22c55e;
        }
        body {
            font-family: system-ui, -apple-system, sans-serif;
            background: var(--bg);
            color: var(--text);
            margin: 0;
            padding: 2rem;
            display: flex;
            justify-content: center;
        }
        .container {
            max-width: 760px;
            width: 100%;
            background: var(--card);
            padding: 2rem;
            border-radius: 14px;
            box-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.5);
        }
        h1 { margin-top: 0; color: var(--accent); font-size: 1.6rem; }
        .input-group { margin-bottom: 1.2rem; }
        label { display: block; margin-bottom: 0.4rem; color: var(--muted); font-size: 0.9rem; }
        input {
            width: 100%;
            padding: 0.75rem;
            border-radius: 8px;
            border: 1px solid #334155;
            background: #0f172a;
            color: #fff;
            font-size: 1rem;
            box-sizing: border-box;
        }
        .bar-bg {
            width: 100%;
            height: 12px;
            background: #334155;
            border-radius: 6px;
            overflow: hidden;
            margin: 1rem 0;
        }
        .bar-fill {
            height: 100%;
            width: 0%;
            transition: width 0.3s ease, background 0.3s ease;
        }
        .metrics {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
            gap: 0.8rem;
            margin-bottom: 1.2rem;
        }
        .metric-box {
            background: #0f172a;
            padding: 0.8rem;
            border-radius: 8px;
            border: 1px solid #334155;
        }
        .metric-box span { display: block; font-size: 0.78rem; color: var(--muted); }
        .metric-box strong { font-size: 1.05rem; }
        button {
            background: var(--accent);
            color: #0f172a;
            font-weight: 700;
            border: none;
            padding: 0.75rem 1.2rem;
            border-radius: 8px;
            cursor: pointer;
        }
        .suggestion {
            background: #0f172a;
            padding: 0.75rem;
            border-radius: 8px;
            margin-top: 0.5rem;
            font-family: monospace;
            border-left: 4px solid var(--accent);
        }
        .status-msg { margin-top: 1rem; padding: 0.8rem; border-radius: 8px; display: none; }
    </style>
</head>
<body>
<div class="container">
    <h1>🔐 Password Strength Analyzer & Crypto Reuse Guard</h1>
    <div class="input-group">
        <label>Username (for PBKDF2-HMAC-SHA256 Reuse History Check)</label>
        <input type="text" id="username" placeholder="e.g., priyanshu" value="demo_user">
    </div>
    <div class="input-group">
        <label>Enter Password to Evaluate</label>
        <input type="text" id="password" placeholder="Type a password..." oninput="analyzePassword()">
    </div>
    <div class="bar-bg"><div class="bar-fill" id="bar"></div></div>
    <div class="metrics">
        <div class="metric-box"><span>Score & Rating</span><strong id="score">0 / 100</strong></div>
        <div class="metric-box"><span>Pool Entropy</span><strong id="entropy">0 bits</strong></div>
        <div class="metric-box"><span>Est. Crack Time</span><strong id="crack">Instant</strong></div>
        <div class="metric-box"><span>Uniqueness</span><strong id="unique">0%</strong></div>
    </div>
    <div id="feedback"></div>
    <div id="suggestions"></div>
    <div style="margin-top: 1.4rem;">
        <button onclick="savePassword()">Save to Salted Hash DB (Test Reuse Prevention)</button>
        <div id="dbStatus" class="status-msg"></div>
    </div>
</div>
<script>
async function analyzePassword() {
    const pw = document.getElementById('password').value;
    const res = await fetch('/api/analyze', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({password: pw})
    });
    const data = await res.json();
    const a = data.analysis;
    const bar = document.getElementById('bar');
    bar.style.width = a.score + '%';
    bar.style.background = a.score < 50 ? '#ef4444' : (a.score < 75 ? '#f59e0b' : '#22c55e');
    document.getElementById('score').textContent = `${a.score}/100 (${a.rating})`;
    document.getElementById('entropy').textContent = `${a.pool_entropy_bits} bits`;
    document.getElementById('crack').textContent = a.estimated_crack_time;
    document.getElementById('unique').textContent = `${Math.round(a.uniqueness_ratio * 100)}% (${a.unique_chars}/${a.password_length})`;

    let fb = '';
    if (a.vulnerabilities.length) {
        fb += '<h4>⚠️ Vulnerabilities</h4><ul>' + a.vulnerabilities.map(v => `<li>${v}</li>`).join('') + '</ul>';
    }
    document.getElementById('feedback').innerHTML = fb;

    let sug = '<h4>🛡️ Suggested Stronger Alternatives</h4>';
    data.suggestions.forEach(s => {
        sug += `<div class="suggestion"><strong>${s.type}:</strong> ${s.password}<br><small style="color:#94a3b8">${s.description}</small></div>`;
    });
    document.getElementById('suggestions').innerHTML = sug;
}

async function savePassword() {
    const username = document.getElementById('username').value;
    const password = document.getElementById('password').value;
    const res = await fetch('/api/save', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({username, password})
    });
    const data = await res.json();
    const box = document.getElementById('dbStatus');
    box.style.display = 'block';
    box.style.background = data.success ? 'rgba(34,197,94,0.18)' : 'rgba(239,68,68,0.18)';
    box.textContent = data.message;
}
</script>
</body>
</html>
"""


@app.route("/")
def index():
    return render_template_string(HTML_TEMPLATE)


@app.route("/api/analyze", methods=["POST"])
def api_analyze():
    payload = request.get_json(force=True)
    pw = payload.get("password", "")
    analysis = PasswordAnalyzer.analyze(pw)
    suggestions = PasswordGenerator.suggest_alternatives(pw)
    return jsonify({
        "analysis": analysis.to_dict(),
        "suggestions": suggestions
    })


@app.route("/api/save", methods=["POST"])
def api_save():
    payload = request.get_json(force=True)
    username = payload.get("username", "default_user")
    pw = payload.get("password", "")
    analysis = PasswordAnalyzer.analyze(pw)
    success, message = db.store_password(
        username=username,
        password=pw,
        entropy_bits=analysis.pool_entropy_bits,
        score=analysis.score
    )
    return jsonify({"success": success, "message": message})


if __name__ == "__main__":
    app.run(debug=True, port=5000)
