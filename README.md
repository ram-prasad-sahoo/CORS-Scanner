<div align="center">

# 🔐 CORS Exploit Scanner
### Ultimate Edition

> A powerful, browser-based **Cross-Origin Resource Sharing (CORS)** vulnerability testing tool —  
> built for security professionals, penetration testers, and researchers.

[![Python](https://img.shields.io/badge/Python-3.8%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![Flask](https://img.shields.io/badge/Flask-Framework-000000?style=for-the-badge&logo=flask&logoColor=white)](https://flask.palletsprojects.com)
[![SQLite](https://img.shields.io/badge/SQLite-Database-003B57?style=for-the-badge&logo=sqlite&logoColor=white)](https://sqlite.org)
[![License](https://img.shields.io/badge/License-MIT-22c55e?style=for-the-badge)](LICENSE)
[![Live Demo](https://img.shields.io/badge/Live%20Demo-Online-e11d48?style=for-the-badge&logo=googlechrome&logoColor=white)](https://corschecker.pythonanywhere.com/)

---

**[🌐 Live Demo](https://corschecker.pythonanywhere.com/)** &nbsp;•&nbsp; **[📖 Docs](#-how-it-works)** &nbsp;•&nbsp; **[🚀 Quick Start](#-installation)** &nbsp;•&nbsp; **[🧩 Features](#-features)**

</div>

---

## ✨ Features

<table>
<tr>
<td width="50%">

### 🎯 56+ Exploit Vectors
Tests edge-cases most scanners miss:

- 🔹 Null Byte Injection
- 🔹 Unicode Origin Bypass
- 🔹 Protocol Downgrade Attacks
- 🔹 URL Encoding Tricks
- 🔹 Safari / Chrome Extension Quirks
- 🔹 Explicit Port Routing
- 🔹 Subdomain Wildcard Fuzzing
- 🔹 Pre-domain & Post-domain Injection

</td>
<td width="50%">

### ⚡ 3 Scanning Modes

| Mode | Vectors | Speed |
|------|---------|-------|
| **Normal** | 11 fundamental checks | ⚡ Fast |
| **Aggressive** | All 56+ vectors | 🔥 Thorough |
| **Stealth** | All 56 + random delay | 🕵️ WAF-Evasive |

> Stealth mode randomizes delays between **300ms – 1000ms** to evade WAF detection.

</td>
</tr>
<tr>
<td width="50%">

### 🧪 PoC Payload Generator
Instantly generate exploit code for **5 environments**:

```
✅ HTML Page      ✅ Fetch API
✅ XHR Request    ✅ cURL Command
✅ Python Script
```
One-click copy — ready to use immediately.

</td>
<td width="50%">

### 🔐 Auth Injection Support
Test all vectors with full authentication context:

- 🍪 Browser Session Cookies
- 🪙 Bearer Token Headers
- 🌐 Forced Origin Overwrite

</td>
</tr>
</table>

### 🖥️ More Capabilities

| Feature | Description |
|---------|-------------|
| **Resizable UI** | Split.js dashboard — drag to resize the response pane or vector log |
| **Admin Dashboard** | Real-time SQLite logging with verdict statistics for every scan |
| **History Export** | Single-click export of full scan history |
| **Verdict Engine** | Auto-classifies findings: `Safe` / `Misconfigured` / `Critical ATO` |

---

## 🚀 Installation

### Requirements

| Requirement | Version |
|------------|---------|
| Python | `3.8+` |
| Flask | Latest |

### Setup

```bash
# 1. Clone the repository
git clone https://github.com/ram-prasad-sahoo/CORS-Scanner.git
cd CORS-Scanner

# 2. Install dependencies
pip install -r requirements.txt

# 3. Launch the application
python app.py
```

```
🌐  App running at →   http://127.0.0.1:5000/
🛡️  Admin panel  →   http://127.0.0.1:5000/admin
📖  Docs         →   http://127.0.0.1:5000/docs
```

### ☁️ Or Use the Web Version

No setup needed — test directly in your browser:

🔗 **[https://corschecker.pythonanywhere.com/](https://corschecker.pythonanywhere.com/)**

---

## 🗄️ Admin Dashboard

All scans — safe or vulnerable — are automatically logged to `cors_scans.db` and visible in the Admin Dashboard.

```
📍  URL       →  http://127.0.0.1:5000/admin
👤  Username  →  admin
🔑  Password  →  admin
```

> ⚠️ **Security Notice:** Change the default credentials in `app.py` before deploying to any external or shared network.

---

## 🔬 How It Works

The scanner sends crafted HTTP requests with manipulated `Origin` headers to the target and analyzes the server's `Access-Control-Allow-Origin` (ACAO) response.

```
┌──────────────────────────────────────────────────────────┐
│                   CORS SCAN LIFECYCLE                    │
├──────────────────────────────────────────────────────────┤
│                                                          │
│  [1] Origin Fuzzing  →  Inject crafted Origin variants   │
│                                                          │
│  [2] Header Parsing  →  Read ACAO + ACAC headers         │
│                                                          │
│  [3] Verdict Engine  →  Safe / Misconfigured / ATO       │
│                                                          │
│  [4] PoC Generation  →  Build ready-to-use exploit code  │
│                                                          │
└──────────────────────────────────────────────────────────┘
```

Click **📖 DOCS** in the app's top-right corner (or navigate to `/docs`) for a full in-depth breakdown of the fuzzer logic, ACAO header parsing, and ATO classification.

---

## 🧩 Exploit Vector Categories

<details>
<summary><strong>📂 Click to expand all 56+ vector categories</strong></summary>

<br/>

| Category | Description |
|----------|-------------|
| **Wildcard Reflection** | Tests for `*`, `null`, and exact origin reflection |
| **Subdomain Injection** | `evil.target.com`, `target.com.evil.com` |
| **Protocol Downgrade** | Forces `http://` instead of `https://` |
| **Null Origin** | Sandboxed iframe bypass using `null` |
| **URL Encoding** | `%00`, `%20`, and encoded delimiters |
| **Unicode Normalization** | Homoglyph domains and Unicode tricks |
| **Port Variations** | `:80`, `:443`, and non-standard ports |
| **Prefix / Suffix Bypass** | Pre-domain and post-domain injection |
| **Browser-Specific** | Safari quirks, Chrome extension origins |
| **Nested Subdomain** | Multi-level subdomain manipulation |

</details>

---

## ⚖️ Disclaimer

> **This tool is strictly intended for educational purposes and authorized penetration testing only.**
>
> ❌ Do **NOT** use this tool against any infrastructure without **explicit written permission** from the owner.
>
> The authors bear **no responsibility** for any misuse, damage, or legal consequences resulting from unauthorized use of this software.

---

## 🤝 Contributing

Contributions are welcome! To add a new CORS bypass vector or a feature:

```bash
# 1. Fork the repo and clone it
git checkout -b feature/your-feature-name

# 2. Make your changes, then commit
git commit -m "Add: description of your change"

# 3. Push and open a Pull Request
git push origin feature/your-feature-name
```

---

<div align="center">

Made with ❤️ for the security research community

⭐ **Star this repo if you find it useful!**

[![GitHub stars](https://img.shields.io/github/stars/ram-prasad-sahoo/CORS-Scanner?style=social)](https://github.com/ram-prasad-sahoo/CORS-Scanner)

</div>
