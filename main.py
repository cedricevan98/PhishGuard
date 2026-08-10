"""
PhishGuard - ML-powered phishing URL detection API
FastAPI backend with feature extraction + Random Forest classifier
"""

from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, HttpUrl
from typing import Optional, List
import re
import math
import time
import hashlib
import sqlite3
import logging
from pathlib import Path
from datetime import datetime
from urllib.parse import urlparse

import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
import joblib

# ──────────────────────────────────────────────
#  Logging
# ──────────────────────────────────────────────
logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(levelname)s | %(message)s")
logger = logging.getLogger(__name__)

# ──────────────────────────────────────────────
#  App
# ──────────────────────────────────────────────
app = FastAPI(
    title="PhishGuard API",
    description="ML-powered phishing URL detection with explainable risk scores",
    version="1.0.0",
    docs_url="/docs",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ──────────────────────────────────────────────
#  Database (SQLite for scan history)
# ──────────────────────────────────────────────
DB_PATH = Path("phishguard.db")

def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            url         TEXT NOT NULL,
            url_hash    TEXT NOT NULL,
            is_phishing INTEGER NOT NULL,
            confidence  REAL NOT NULL,
            risk_score  REAL NOT NULL,
            scanned_at  TEXT NOT NULL
        )
    """)
    conn.commit()
    conn.close()

init_db()

# ──────────────────────────────────────────────
#  Suspicious keyword lists
# ──────────────────────────────────────────────
PHISHING_KEYWORDS = [
    "secure", "account", "update", "login", "signin", "verify",
    "banking", "paypal", "ebay", "amazon", "apple", "microsoft",
    "confirm", "password", "credential", "suspended", "alert",
    "unusual", "activity", "limited", "urgent", "click", "immediately",
]

TRUSTED_TLDS = {".com", ".org", ".net", ".gov", ".edu", ".io"}
SUSPICIOUS_TLDS = {".xyz", ".top", ".click", ".gq", ".tk", ".ml", ".ga", ".cf"}

# ──────────────────────────────────────────────
#  Feature Extraction
# ──────────────────────────────────────────────
def extract_features(url: str) -> dict:
    """Extract 20 statistical and lexical features from a URL."""
    try:
        parsed = urlparse(url if url.startswith("http") else f"http://{url}")
    except Exception:
        parsed = urlparse(f"http://{url}")

    hostname = parsed.hostname or ""
    path = parsed.path or ""
    full = url.lower()

    # Lexical
    url_length = len(url)
    num_dots = url.count(".")
    num_hyphens = url.count("-")
    num_underscores = url.count("_")
    num_slashes = url.count("/")
    num_at = url.count("@")
    num_question = url.count("?")
    num_equals = url.count("=")
    num_digits = sum(c.isdigit() for c in url)
    digit_ratio = num_digits / max(url_length, 1)

    # Entropy of hostname
    if hostname:
        freq = {c: hostname.count(c) / len(hostname) for c in set(hostname)}
        entropy = -sum(p * math.log2(p) for p in freq.values() if p > 0)
    else:
        entropy = 0.0

    # Subdomain depth
    subdomain_depth = max(0, len(hostname.split(".")) - 2)

    # IP address in hostname
    ip_pattern = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
    has_ip = int(bool(ip_pattern.match(hostname)))

    # HTTPS
    has_https = int(parsed.scheme == "https")

    # Suspicious TLD
    tld = "." + hostname.split(".")[-1] if "." in hostname else ""
    suspicious_tld = int(tld in SUSPICIOUS_TLDS)

    # Keyword presence
    keyword_count = sum(1 for kw in PHISHING_KEYWORDS if kw in full)

    # Hex encoding in URL
    has_hex = int(bool(re.search(r"%[0-9a-f]{2}", full)))

    # Long path
    long_path = int(len(path) > 50)

    # Punycode (IDN homograph attacks)
    has_punycode = int("xn--" in hostname)

    return {
        "url_length": url_length,
        "num_dots": num_dots,
        "num_hyphens": num_hyphens,
        "num_underscores": num_underscores,
        "num_slashes": num_slashes,
        "num_at": num_at,
        "num_question": num_question,
        "num_equals": num_equals,
        "digit_ratio": digit_ratio,
        "entropy": entropy,
        "subdomain_depth": subdomain_depth,
        "has_ip": has_ip,
        "has_https": has_https,
        "suspicious_tld": suspicious_tld,
        "keyword_count": keyword_count,
        "has_hex": has_hex,
        "long_path": long_path,
        "has_punycode": has_punycode,
    }


def compute_risk_score(features: dict, ml_confidence: float, is_phishing: bool) -> float:
    """Weighted risk score 0–100 combining ML confidence + heuristics."""
    base = ml_confidence * 60 if is_phishing else (1 - ml_confidence) * 10

    # Additive heuristic penalties
    penalties = 0
    penalties += min(features["keyword_count"] * 5, 20)
    penalties += features["has_ip"] * 15
    penalties += features["has_punycode"] * 10
    penalties += features["suspicious_tld"] * 8
    penalties += features["num_at"] * 10
    penalties += max(0, features["subdomain_depth"] - 2) * 5
    penalties -= features["has_https"] * 5  # slight bonus

    return round(min(100, max(0, base + penalties)), 1)


# ──────────────────────────────────────────────
#  Mock ML Model (replace with real trained model)
# ──────────────────────────────────────────────
MODEL_PATH = Path("phishguard_model.joblib")

def _train_mock_model():
    """Train a small demo model so the API works out of the box."""
    logger.info("Training demo model...")
    rng = np.random.default_rng(42)
    n = 500

    # Simple synthetic data: phishing URLs tend to have higher feature values
    X_phish = rng.normal(loc=[80, 4, 3, 1, 5, 0.5, 1, 2, 0.3, 3.5, 2, 0.4, 0.3, 0.6, 3, 0.3, 0.5, 0.2], scale=0.3, size=(n // 2, 18))
    X_legit = rng.normal(loc=[30, 2, 0, 0, 2, 0,   0, 0, 0.05,2.0, 0, 0,   0.9, 0,   0, 0,   0,   0  ], scale=0.3, size=(n // 2, 18))
    X = np.vstack([X_phish, X_legit])
    y = np.array([1] * (n // 2) + [0] * (n // 2))

    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    clf = RandomForestClassifier(n_estimators=100, random_state=42)
    clf.fit(X_scaled, y)

    joblib.dump({"model": clf, "scaler": scaler}, MODEL_PATH)
    logger.info("Demo model saved.")
    return clf, scaler


if MODEL_PATH.exists():
    _saved = joblib.load(MODEL_PATH)
    _model, _scaler = _saved["model"], _saved["scaler"]
else:
    _model, _scaler = _train_mock_model()


def predict(features: dict) -> tuple[bool, float]:
    """Return (is_phishing, confidence)."""
    vec = np.array([list(features.values())], dtype=float)
    vec_scaled = _scaler.transform(vec)
    prob = _model.predict_proba(vec_scaled)[0]
    is_phishing = bool(prob[1] > 0.5)
    confidence = float(max(prob))
    return is_phishing, confidence


# ──────────────────────────────────────────────
#  Schemas
# ──────────────────────────────────────────────
class ScanRequest(BaseModel):
    url: str
    save_history: bool = True


class BatchScanRequest(BaseModel):
    urls: List[str]


class ScanResult(BaseModel):
    url: str
    is_phishing: bool
    confidence: float
    risk_score: float
    verdict: str
    features: dict
    scanned_at: str


class BatchScanResult(BaseModel):
    total: int
    phishing_count: int
    results: List[ScanResult]


class StatsResponse(BaseModel):
    total_scanned: int
    total_phishing: int
    phishing_rate: float
    recent_threats: List[dict]


# ──────────────────────────────────────────────
#  Routes
# ──────────────────────────────────────────────
@app.get("/", tags=["Health"])
async def root():
    return {"service": "PhishGuard", "version": "1.0.0", "status": "operational"}


@app.get("/health", tags=["Health"])
async def health():
    return {"status": "ok", "model_loaded": MODEL_PATH.exists()}


@app.post("/scan", response_model=ScanResult, tags=["Detection"])
async def scan_url(req: ScanRequest):
    """Scan a single URL for phishing indicators."""
    url = req.url.strip()
    if not url:
        raise HTTPException(status_code=400, detail="URL cannot be empty")

    features = extract_features(url)
    is_phishing, confidence = predict(features)
    risk_score = compute_risk_score(features, confidence, is_phishing)

    if risk_score >= 70:
        verdict = "🔴 PHISHING"
    elif risk_score >= 40:
        verdict = "🟡 SUSPICIOUS"
    else:
        verdict = "🟢 SAFE"

    scanned_at = datetime.utcnow().isoformat()

    if req.save_history:
        url_hash = hashlib.sha256(url.encode()).hexdigest()
        conn = sqlite3.connect(DB_PATH)
        conn.execute(
            "INSERT INTO scans (url, url_hash, is_phishing, confidence, risk_score, scanned_at) VALUES (?,?,?,?,?,?)",
            (url, url_hash, int(is_phishing), confidence, risk_score, scanned_at),
        )
        conn.commit()
        conn.close()

    return ScanResult(
        url=url,
        is_phishing=is_phishing,
        confidence=round(confidence, 4),
        risk_score=risk_score,
        verdict=verdict,
        features=features,
        scanned_at=scanned_at,
    )


@app.post("/scan/batch", response_model=BatchScanResult, tags=["Detection"])
async def batch_scan(req: BatchScanRequest):
    """Scan up to 50 URLs in one request."""
    if len(req.urls) > 50:
        raise HTTPException(status_code=400, detail="Maximum 50 URLs per batch request")

    results = []
    for url in req.urls:
        r = await scan_url(ScanRequest(url=url, save_history=True))
        results.append(r)

    phishing = [r for r in results if r.is_phishing]
    return BatchScanResult(
        total=len(results),
        phishing_count=len(phishing),
        results=results,
    )


@app.get("/stats", response_model=StatsResponse, tags=["Analytics"])
async def get_stats():
    """Return aggregate statistics from the scan history."""
    conn = sqlite3.connect(DB_PATH)
    total = conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
    phishing = conn.execute("SELECT COUNT(*) FROM scans WHERE is_phishing=1").fetchone()[0]
    recent = conn.execute(
        "SELECT url, risk_score, verdict, scanned_at FROM scans ORDER BY id DESC LIMIT 10"
    ).fetchall()
    conn.close()

    recent_threats = [
        {"url": r[0][:60] + "..." if len(r[0]) > 60 else r[0], "risk_score": r[1], "scanned_at": r[3]}
        for r in recent
    ]

    return StatsResponse(
        total_scanned=total,
        total_phishing=phishing,
        phishing_rate=round(phishing / total * 100, 2) if total else 0.0,
        recent_threats=recent_threats,
    )


@app.delete("/history", tags=["Analytics"])
async def clear_history():
    """Clear all scan history from the local database."""
    conn = sqlite3.connect(DB_PATH)
    conn.execute("DELETE FROM scans")
    conn.commit()
    conn.close()
    return {"message": "Scan history cleared"}


# ──────────────────────────────────────────────
#  Entry point
# ──────────────────────────────────────────────
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
