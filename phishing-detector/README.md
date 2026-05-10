# PhishGuard — Email Threat Analyzer

A full-stack cybersecurity tool that analyzes emails for phishing indicators and displays results on a real-time dashboard.

![PhishGuard](https://img.shields.io/badge/Security-Phishing%20Detector-red) ![Python](https://img.shields.io/badge/Python-3.8+-blue) ![React](https://img.shields.io/badge/React-18-61dafb) ![Flask](https://img.shields.io/badge/Flask-3.0-green)

---

## Features

- **URL Analysis** — Detects URL shorteners, IP-based links, suspicious TLDs, and brand impersonation
- **Sender Analysis** — Checks display name spoofing, domain impersonation, and suspicious sender domains  
- **Content Analysis** — Scans for phishing keywords, urgency language, and requests for sensitive info
- **Risk Scoring** — Weighted 0–100 score across all three vectors
- **Scan History** — Tracks all previous scans in-session
- **Sample Emails** — Built-in phishing, suspicious, and safe samples to test with
- **Dark dashboard** — Clean, professional React UI

---

## Tech Stack

| Layer | Technology |
|---|---|
| Backend | Python, Flask, Flask-CORS |
| Frontend | React 18, Vite |
| Styling | Custom CSS (Space Grotesk, JetBrains Mono) |
| Analysis | Custom rule engine (no ML dependencies) |

---

## Project Structure

```
phishing-detector/
├── backend/
│   ├── app.py          # Flask API server
│   ├── analyzer.py     # Detection engine
│   └── requirements.txt
├── frontend/
│   ├── src/
│   │   ├── App.jsx     # Main React component
│   │   └── App.css     # Stylesheet
│   ├── index.html
│   ├── package.json
│   └── vite.config.js
└── README.md
```

---

## Getting Started

### 1. Clone the repo

```bash
git clone https://github.com/YOUR_USERNAME/phishing-detector.git
cd phishing-detector
```

### 2. Start the backend

```bash
cd backend
pip install -r requirements.txt
python app.py
```

Flask will run at `http://localhost:5000`

### 3. Start the frontend

```bash
cd frontend
npm install
npm run dev
```

React will run at `http://localhost:3000`

Open your browser at **http://localhost:3000** to use the app.

---

## API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/api/analyze` | Analyze an email |
| `GET` | `/api/history` | Get scan history |
| `GET` | `/api/stats` | Get summary stats |
| `GET` | `/api/health` | Health check |

### POST `/api/analyze` — Example

**Request:**
```json
{
  "sender": "security@paypal-alert.xyz",
  "subject": "URGENT: Verify your account",
  "email": "Dear Customer, click here to verify: http://bit.ly/paypal-verify"
}
```

**Response:**
```json
{
  "verdict": "phishing",
  "verdict_label": "Phishing Detected",
  "risk_score": 87,
  "url_score": 60,
  "sender_score": 75,
  "content_score": 45,
  "findings": [
    { "category": "URL", "reason": "URL shortener detected", "severity": "high" },
    { "category": "Sender", "reason": "Domain appears to impersonate paypal.com", "severity": "high" }
  ],
  "urls_found": ["http://bit.ly/paypal-verify"]
}
```

---

## How Detection Works

### Verdict Thresholds
| Verdict | Score | Meaning |
|---|---|---|
| Phishing | ≥ 65 | High confidence threat |
| Suspicious | 35–64 | Proceed with caution |
| Safe | < 35 | No significant threats |

### Risk Score Formula
```
risk_score = (url_score × 0.35) + (sender_score × 0.35) + (content_score × 0.30)
```

### URL Checks
- URL shortener domains (bit.ly, tinyurl, etc.)
- IP addresses used as domains
- Suspicious TLDs (.xyz, .top, .click, .tk, etc.)
- Brand impersonation in domain names
- Excessive hyphens in domain

### Sender Checks
- Display name vs. actual domain mismatch
- Domain impersonation of known brands
- Suspicious TLDs in sender domain
- IP-based sender addresses

### Content Checks
- 30+ phishing keyword patterns
- 15+ urgency phrases
- Requests for sensitive information (SSN, passwords, bank accounts)
- Excessive capitalization
- Excessive exclamation marks

---

## Skills Demonstrated

- Python backend development with REST APIs
- React frontend with real-time state management
- Regex-based pattern matching and NLP heuristics
- Security analysis techniques (indicator extraction, risk scoring)
- Full-stack integration (Flask + React)
- Clean API design with structured JSON responses

---

## License

MIT — free to use and modify for learning purposes.
