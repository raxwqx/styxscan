# 🕷️ StyxScan

> Lightweight HTTP & TLS reconnaissance tool for security testing.

**StyxScan** is a lightweight Python-based reconnaissance tool designed to collect useful HTTP, HTTPS, DNS, TLS, and redirect information from a target.

Built for security researchers, penetration testers, and curious hackers.

---

## ⚡ Features

* 🌐 HTTP / HTTPS information gathering
* 🔐 TLS certificate inspection
* 🔎 DNS resolution
* ↪️ Redirect history tracking
* ⏱️ Configurable request timeout
* 📄 JSON output
* 🌐 HTML report generation
* 🚫 Disable DNS resolution with `--no-dns`
* 🚫 Disable TLS inspection with `--no-tls`
* 🧪 Automated test suite
* 🐍 Python-based and lightweight CLI

---

## 📦 Installation

Clone the repository:

```bash
git clone https://github.com/raxwqx/styxscan.git
cd styxscan
```

Install dependencies:

```bash
pip install -r requirements.txt
```

Or install the project with:

```bash
pip install .
```

---

## 🚀 Usage

Basic scan:

```bash
python styxscan.py https://example.com
```

Disable DNS resolution:

```bash
python styxscan.py https://example.com --no-dns
```

Disable TLS inspection:

```bash
python styxscan.py https://example.com --no-tls
```

Set a custom timeout:

```bash
python styxscan.py https://example.com --timeout 10
```

Generate JSON output:

```bash
python styxscan.py https://example.com --json
```

Generate an HTML report:

```bash
python styxscan.py https://example.com --html
```

---

## 📊 Information Collected

Depending on the target and enabled options, StyxScan can collect:

* Target URL
* HTTP status code
* Response headers
* Server information
* Redirect history
* DNS information
* TLS certificate information
* TLS version
* Connection details
* Response timing

---

## 🧪 Testing

Run the test suite with:

```bash
pytest
```

The project includes automated tests covering the core functionality of StyxScan.

---

## 🗂️ Project Structure

```text
styxscan/
├── styxscan.py
├── pyproject.toml
├── requirements.txt
├── tests/
│   └── ...
├── .gitignore
└── README.md
```

---

## ⚠️ Legal Disclaimer

StyxScan is intended for **authorized security testing, research, and educational purposes only**.

Do not scan systems, networks, or applications without explicit permission from the owner.

The author is not responsible for misuse or damage caused by this tool.

---

## 📜 License

This project is licensed under the **MIT License**.

See the `LICENSE` file for details.

---

## 🕸️ Project

**StyxScan v0.1.0**

Developed by **raxwqx**

GitHub:
https://github.com/raxwqx/styxscan
