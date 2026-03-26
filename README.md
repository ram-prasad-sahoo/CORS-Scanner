# CORS Exploit Scanner — Ultimate Edition

A powerful, browser-based Cross-Origin Resource Sharing (CORS) vulnerability testing tool. It comes equipped with 56+ exploit vectors to thoroughly assess API security, and an automated exploit payload generator that creates ready-to-use Proof-of-Concept (PoC) code in HTML, JavaScript, cURL, and Python.

## Features
- **56+ Exploit Vectors**: Evaluates edge-cases including Null Byte injection, Unicode, Protocol Downgrades, URL Encoding, Safari/Chrome Extension quirks, and explicit Port routing.
- **3 Scanning Modes**:
  - **Normal**: Tests 11 fundamental CORS misconfigurations (fast).
  - **Aggressive**: Tests all 56+ exploit vectors recursively.
  - **Stealth**: Tests all 56 vectors randomly between 300ms and 1000ms delays to evade WAFs.
- **PoC Generator**: Instantly generates exploit payloads for 5 different environments (HTML page, fetch, XHR, cURL, Python) with one-click copy.
- **Auth Injection**: Test CORS vectors with browser session cookies, Bearer tokens, or forced Origin overwrites.
- **Resizable UI**: Interactive Split.js dashboard so you can maximize the raw response payload or vector status logs.
- **Admin Dashboard**: Real-time DB logging of scans, verdict statistics, and single-click history export (SQLite backend).

## Requirements
- Python 3.8+
- Flask

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/ram-prasad-sahoo/CORS-Scanner.git
   cd CORS-Scanner
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Run the application:
   ```bash
   python app.py
   ```

4. Open your browser to:
   ```text
   http://127.0.0.1:5000/
   ```
```md
5. Open In web:  
   [Open in Web](https://corschecker.pythonanywhere.com/)
```

## Admin Dashboard

All executed scans, safe or vulnerable, are logged in the SQLite database (`cors_scans.db`) and are visible in the Admin Dashboard at `http://127.0.0.1:5000/admin`.

**Default Login:**
- **Username:** `admin`
- **Password:** `admin`

*(You are highly encouraged to change these in `app.py` before hosting on an external network)*

## How it works

See the `/docs` page in the application or click **"📖 DOCS"** in the top-right corner to read an in-depth breakdown of how the Fuzzer interprets the `Origin` parameter, parses ACAO headers, and decides whether a potential vulnerability translates into critical Account Takeover (ATO) execution.

## Disclaimer

This tool is strictly for educational purposes and authorized penetration testing only. Do not use against infrastructure without explicit permission. The authors are not responsible for any misuse or damage caused by this program.
