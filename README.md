# 🛡️ PhishGuard

![Python](https://img.shields.io/badge/Python-3.11+-blue?logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-0.111-009688?logo=fastapi&logoColor=white)
![scikit-learn](https://img.shields.io/badge/scikit--learn-1.4-F7931E?logo=scikit-learn&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green)
![Status](https://img.shields.io/badge/Status-Active-brightgreen)

**ML-powered phishing URL detection REST API with explainable risk scores.**

PhishGuard extracts 18 lexical and statistical features from any URL and runs them through a Random Forest classifier to detect phishing attempts in milliseconds. Every scan returns a human-readable verdict, a 0–100 risk score, and the full feature breakdown so you can understand *why* a URL is flagged.

---

## ✨ Features

- **Real-time detection** — scan any URL in < 50 ms
- **18 extracted features** — URL length, entropy, subdomain depth, TLD reputation, keyword patterns, homograph detection (Punycode), IP-in-hostname, and more
- **Explainable scores** — every result ships with the full feature vector so you can audit the decision
- **Batch scanning** — analyse up to 50 URLs in a single request
- **Scan history** — SQLite-backed history with aggregate statistics endpoint
- **Swagger UI** — interactive API docs at `/docs`
- **Docker-ready** — runs in a single container

---

## 🚀 Quick Start

```bash
# Clone
git clone https://github.com/cedricevan98/PhishGuard.git
cd PhishGuard

# Install dependencies
pip install -r requirements.txt

# Start the API
python main.py
# → http://localhost:8000
# → http://localhost:8000/docs  (Swagger UI)
```

---

## 📡 API Reference

### `POST /scan`
Scan a single URL.

```bash
curl -X POST http://localhost:8000/scan \
  -H "Content-Type: application/json" \
  -d '{"url": "http://paypa1-secure-login.tk/verify?user=1234"}'
```

**Response:**
```json
{
  "url": "http://paypa1-secure-login.tk/verify?user=1234",
  "is_phishing": true,
  "confidence": 0.94,
  "risk_score": 87.5,
  "verdict": "🔴 PHISHING",
  "features": {
    "url_length": 45,
    "entropy": 3.87,
    "keyword_count": 3,
    "suspicious_tld": 1,
    "has_ip": 0,
    ...
  },
  "scanned_at": "2024-08-10T12:00:00"
}
```

### `POST /scan/batch`
Scan up to 50 URLs at once.

```bash
curl -X POST http://localhost:8000/scan/batch \
  -H "Content-Type: application/json" \
  -d '{"urls": ["https://google.com", "http://evil-bank.tk/login"]}'
```

### `GET /stats`
Returns aggregate statistics (total scanned, phishing rate, recent threats).

---

## 🧠 How It Works

```
URL Input
   │
   ▼
Feature Extraction (18 features)
   ├─ Lexical: length, dots, hyphens, digits, special chars
   ├─ Structural: subdomain depth, path length, HTTPS
   ├─ Statistical: Shannon entropy of hostname
   └─ Semantic: phishing keywords, TLD reputation, Punycode
   │
   ▼
Random Forest Classifier
   │
   ▼
Risk Score Engine (ML confidence + heuristic penalties)
   │
   ▼
Verdict + Feature Explanation
```

The model is trained on synthetic data by default. Drop in a `phishguard_model.joblib` (trained on a real dataset like PhishTank or OpenPhish) to upgrade accuracy immediately.

---

## 🔧 Configuration

| Variable | Default | Description |
|---|---|---|
| `HOST` | `0.0.0.0` | API bind address |
| `PORT` | `8000` | API port |
| `DB_PATH` | `phishguard.db` | SQLite database path |
| `MODEL_PATH` | `phishguard_model.joblib` | Pre-trained model path |

---

## 🏗️ Project Structure

```
PhishGuard/
├── main.py            # FastAPI app — features, ML, routes
├── requirements.txt
├── .gitignore
└── README.md
```

---

## 🛣️ Roadmap

- [ ] WHOIS & DNS reputation lookup integration
- [ ] React dashboard with real-time threat map
- [ ] Browser extension (Chrome/Firefox)
- [ ] Model retraining pipeline with PhishTank dataset
- [ ] Webhook alerts for detected threats
- [ ] Docker Compose with Redis caching layer

---

## 📄 License

MIT — see [LICENSE](LICENSE) for details.

---

<p align="center">Built with ❤️ by <a href="https://github.com/cedricevan98">Cedric Evan</a> · Security Engineer & Full-Stack Developer</p>
