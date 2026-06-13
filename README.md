# 🔥 Web Application Firewall - Intrusion Prevention System (WAF IPS)

A complete Python-based Web Application Firewall (WAF) integrated with an Intrusion Prevention System (IPS).
Includes unified UI, dashboard, admin panel, attack simulator, PDF reporting, and a one-click launcher.

---

## 🚀 Features

* Rule-based HTTP request filtering
* SQL Injection detection & blocking
* Attack logging system (`attacks.log`)
* Rate limiting (DoS protection)
* Proxy-based traffic monitoring
* Live attack dashboard
* PDF report generation
* Admin panel with controls
* Attack simulator + comparison mode
* One-click execution using `start_demo.bat`

---

## 🧠 Architecture

Client → WAF Proxy (8080) → Backend + UI Server (5001)

---

## 📁 Project Structure

backend.py        - Unified backend + UI
proxy.py          - WAF proxy server
rules_engine.py   - Detection logic
logger.py         - Logging system
rate_limiter.py   - Rate limiting

dashboard.py      - Dashboard service
report.py         - PDF generator
admin.py          - Admin panel
simulate.py       - Attack simulator

setupdb.py        - Database setup
start_demo.bat    - Master launcher

blocked_ips.json
attacks.log
test.db
requirements.txt

---

## ⚙️ Installation

Clone repository:

git clone https://github.com/rushan-2024/WEB-APPLICATION-FIREWALL---IPS-.git

cd mini_project

Install dependencies:

pip install flask requests fpdf2

---

## ▶️ Run the Project

start_demo.bat

This will:

* Install dependencies
* Setup database
* Start all servers
* Open browser automatically

---

## 🌐 Application Routes

Home: http://localhost:5001

Login: http://localhost:5001/login

Dashboard: http://localhost:5001/dashboard

Simulator: http://localhost:5001/simulate

Comparison: http://localhost:5001/compare

Stats: http://localhost:5001/stats

Admin Panel: http://localhost:5001/admin

PDF Report: http://localhost:5003

---

## 🔐 Admin Credentials

Password: admin123

---

## 🧪 Testing Attack

Example:

/login?user=1 OR 1=1--

Expected:

* Blocked (403)
* Logged in attacks.log
* Visible in dashboard

---

## 🔒 Detected Attacks

* SQL Injection
* SQL Comments (`--`)
* Dangerous Queries (DROP, INSERT, UPDATE)
* DoS via rate limiting

---

## 📊 Demo Flow

1. /stats
2. /login
3. /simulate
4. /compare
5. /dashboard
6. http://localhost:5003/download/pdf
7. /admin

---

## ⚠️ Limitations

* Cannot detect advanced obfuscated attacks
* Limited XSS/CSRF protection
* Basic rate limiting

---

## 🚀 Future Improvements

* AI/ML-based detection
* Advanced payload decoding
* XSS & CSRF protection
* IP banning
* Cloud deployment

---

## 🛠 Tech Stack

Python
Flask
Requests
SQLite
FPDF2

---

## 🤝 Contributing

Fork → Create branch → Submit PR

---


