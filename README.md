# 🔍 Knock Subdomain Scan v8

✅ Fast & Async • 🔐 Recon + Brute • 🔧 Easy to Extend

**KnockPy** is a modular Python 3 tool to enumerate subdomains via passive reconnaissance and bruteforce, now with **async/await support**, enhanced performance, and modern HTTP/TLS handling.

> Version: **8**  
> GitHub: [https://github.com/guelfoweb/knock](https://github.com/guelfoweb/knock)

![knockpy8](https://github.com/guelfoweb/knock/assets/41558/b168f105-720f-4f21-aba1-5be5c0326957)

---

## 🚀 Features (v8)

- ✅ **Async scanning** with `httpx` and DNS resolution
- ✅ Modular: plug new passive sources easily
- 🔍 Supports **passive recon**, **bruteforce**, or both
- 📜 Validates **HTTP/HTTPS status**, **TLS cert**, and **IP**
- 💡 Supports **wildcard DNS** detection
- 🧪 Output as **JSON**, optional save & reload
- 🔐 Supports **VirusTotal** and **Shodan** API

---

## 📦 Installation

### From GitHub source (recommended)

```bash
git clone https://github.com/guelfoweb/knock.git
cd knock
pip install .
```

⚠️ Recommended Python version: 3.9+


### Using pip

*Only after the stable version is released on GitHub*

```bash
pip install knock-subdomains
```

## 🧪 Usage

```bash
knockpy -d domain.com [options]
```

### Options

| Flag              | Description                        |
| ----------------- | ---------------------------------- |
| `-d`, `--domain`  | Target domain                      |
| `-f`, `--file`    | File with list of domains          |
| `--recon`         | Enable passive reconnaissance      |
| `--bruteforce`,`brute`    | Enable bruteforce using wordlist   |
| `--wordlist`      | Custom wordlist (default included) |
| `--dns`           | Custom DNS resolver                |
| `--useragent`     | Custom HTTP user-agent             |
| `--timeout`       | Request timeout in seconds         |
| `--threads`       | Number of concurrent workers       |
| `--wildcard`      | Test wildcard DNS and exit         |
| `--json`          | Output results in JSON             |
| `--save FOLDER`   | Save report to folder              |
| `--report FILE`   | Load and show a saved report       |
| `--silent`        | Hide progress bar                  |
| `--logfile`       | Write debug log to file            |
| `--show-settings` | Print scan settings and continue   |
| `--version`       | Show KnockPy version               |
| `-h`, `--help`    | Show help message                  |


## 📌 Examples

### 🔎 Recon + Brute

```bash
knockpy -d example.com --recon --bruteforce
```

### 🧠 API Keys (optional)

```bash
export API_KEY_VIRUSTOTAL=your-virustotal-api-key
export API_KEY_SHODAN=your-shodan-api-key
```

You can use `.env` file:

```bash
API_KEY_VIRUSTOTAL=your-virustotal-api-key
API_KEY_SHODAN=your-shodan-api-key
```

### 💾 Save and reload report

```bash
knockpy -d example.com --recon --bruteforce --save report/
knockpy --report report/example.com_2025_10_25_14_00_00.json
```

### 🧪 Wildcard test only

```bash
knockpy -d example.com --wildcard
```

## 🧬 Python API Usage

KnockPy can be used as a Python module:

```python
from knock import KNOCKPY

domain = 'example.com'

results = KNOCKPY(
    domain,
    dns="8.8.8.8",
    useragent="Mozilla/5.0",
    timeout=2,
    threads=10,
    recon=True,
    bruteforce=True,
    wordlist=None,
    silent=False
)

for entry in results:
    print(entry['domain'], entry['ip'], entry['http'], entry['cert'])
```

## 📂 Wordlist

A default wordlist is included in `knock/wordlist/wordlist.txt`.
You can supply your own with `--wordlist`.

## Test

```bash
python tests/poc.py
```

## 📖 License

Licensed under the GPLv3 license.
Gianni Amato (@guelfoweb)