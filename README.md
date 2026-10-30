# ScamShield — Smart Scam & Phishing Message Detector

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue.svg)](https://www.python.org/)
[![Flask](https://img.shields.io/badge/Framework-Flask-green.svg)](https://flask.palletsprojects.com/)
[![License](https://img.shields.io/badge/License-MIT-brightgreen.svg)](LICENSE)

**ScamShield** is a web application designed to identify fraudulent communications, SMS scams, phishing attempts, suspicious web links, and social engineering attacks in real time.

---

## 🌟 Key Features
- **Message Analysis Engine:** Rule-based detection checking for urgent payments, lottery claims, OTP theft, bank spoofing, and crypto scams.
- **URL Inspection Engine:** Identifies raw IP hosts, URL shorteners, excessive subdomains, non-HTTPS protocols, and domain brand spoofing.
- **Dynamic Risk Scoring:** Scores risk from 0–100 across 4 classifications: `Low`, `Medium`, `High`, `Critical`.
- **Cybersecurity SaaS Dashboard:** Interactive UI with metrics, sample inputs, copyable reports, and clean navigation.
- **SQLite Scan Log:** Historical record tracking with individual analysis views and log clearing capabilities.

---

## 🛠️ Technology Stack
- **Backend:** Python 3, Flask Framework
- **Database:** SQLite3
- **Frontend:** HTML5, CSS3, Vanilla JavaScript
- **Testing:** Python `unittest`

---

## 🚀 Quick Start Guide

### 1. Clone & Navigate
```bash
git clone https://github.com/your-username/ScamShield.git
cd ScamShield
```

### 2. Install Dependencies
```bash
pip install -r requirements.txt
```

### 3. Run Application
```bash
python app.py
```
Visit `http://127.0.0.1:5000` in your web browser.

---

## 🧪 Running Automated Unit Tests
```bash
python -m unittest discover -s tests
```

---

## 🔒 Security & Privacy Principles
- **Zero Remote Execution:** Never visits or triggers external HTTP requests to submitted links.
- **Privacy First:** Does not collect or store credentials, PINs, or real passwords.
- **Local Database:** Uses parameterized SQLite queries to prevent SQL Injection.
