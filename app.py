print(">>> THIS APP.PY IS RUNNING <<<")

from flask import Flask, render_template, request
import pandas as pd
import joblib
import sqlite3
from urllib.parse import urlparse
from datetime import datetime
from difflib import SequenceMatcher
import os

app = Flask(__name__)

# ---------------- LOAD MODEL ----------------
model = joblib.load("ransomware_model.pkl")

# ---------------- DATABASE ----------------
DB_PATH = os.path.join(os.path.dirname(__file__), "history.db")

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT,
            threat_type TEXT,
            risk_level TEXT,
            score INTEGER,
            time TEXT
        )
    """)
    conn.commit()
    conn.close()

init_db()

# ---------------- TRUSTED DOMAINS ----------------
TRUSTED_DOMAINS = [
    "google.com","youtube.com","gmail.com","facebook.com","instagram.com",
    "linkedin.com","github.com","microsoft.com","amazon.com","apple.com",
    "paypal.com","netflix.com","openai.com","wikipedia.org","stackoverflow.com",
    "twitter.com","x.com","cloudflare.com","oracle.com","ibm.com","zoom.us",
    "spotify.com","reddit.com","quora.com","udemy.com","coursera.org",
    "icici.com","hdfcbank.com","sbi.co.in","axisbank.com","kotak.com",
    "irctc.co.in","india.gov.in","uidai.gov.in","mit.edu","harvard.edu"
]

# ---------------- URL UTILITIES ----------------
def get_domain(url):
    return urlparse(url).netloc.replace("www.", "").lower()

def is_whitelisted(url):
    domain = get_domain(url)
    return any(domain.endswith(td) for td in TRUSTED_DOMAINS)

# ---------------- TYPOSQUATTING ----------------
def is_typosquatting(domain, trusted_domains, threshold=0.8):
    for trusted in trusted_domains:
        similarity = SequenceMatcher(None, domain, trusted).ratio()
        if similarity >= threshold and domain != trusted:
            return True, trusted, round(similarity, 2)
    return False, None, None

# ---------------- FEATURE EXTRACTION ----------------
def extract_features(url):
    return pd.DataFrame([{
        "url_length": len(url),
        "num_digits": sum(c.isdigit() for c in url),
        "num_special_chars": sum(not c.isalnum() for c in url),
        "num_dots": url.count('.'),
        "suspicious_word": sum(
            w in url.lower()
            for w in ['login','secure','update','verify','bank','account']
        )
    }])

# ---------------- RISK LEVEL ----------------
def get_risk(score):
    if score < 25: return "Low"
    elif score < 50: return "Medium"
    elif score < 75: return "High"
    else: return "Critical"

# ---------------- HOME ROUTE ----------------
@app.route("/", methods=["GET", "POST"])
def home():
    result = ""
    risk = ""
    score = 0

    if request.method == "POST":
        url = request.form.get("url", "").strip()
        if not url.startswith(("http://","https://")):
            url = "http://" + url

        if is_whitelisted(url):
            result = "Safe URL ✅ (Whitelisted)"
            risk = "Low"
            score = 0
        else:
            features = extract_features(url)
            prob = model.predict_proba(features)[0]
            malicious_prob = prob[1]

            score = int(malicious_prob*100)
            risk = get_risk(score)

            if malicious_prob > 0.5:
                if any(word in url.lower() for word in ["ransom","encrypt","bitcoin","crypto","locker"]):
                    result = "Ransomware URL ❌"
                else:
                    result = "Malicious URL ⚠️"
            else:
                result = "Safe URL ✅"

        # Save history
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute(
            "INSERT INTO history (url, threat_type, risk_level, score, time) VALUES (?, ?, ?, ?, ?)",
            (url, result, risk, score, datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        )
        conn.commit()
        conn.close()

    return render_template(
        "index.html",
        result=result,
        risk=risk,
        threat_score=score
    )

# ---------------- HISTORY ----------------
@app.route("/history")
def history():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
        SELECT url, threat_type, risk_level, score, time
        FROM history
        ORDER BY id DESC
    """)
    data = c.fetchall()
    conn.close()
    return render_template("history.html", data=data)

# ---------------- RUN ----------------
if __name__ == "__main__":
    # Use environment port for deployment (Render, Cloud, etc.)
    port = int(os.environ.get("PORT", 8000))
    app.run(host="0.0.0.0", port=port)
    