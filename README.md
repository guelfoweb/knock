# Knock Subdomain Scan v7

:heavy_check_mark: Fast :heavy_check_mark: Easy :heavy_check_mark: Modular

**Knockpy** is a portable and modular `python3` tool designed to quickly enumerate subdomains on a target domain through *passive reconnaissance* and *dictionary scan*.

![knockpy7](https://github.com/guelfoweb/knock/assets/41558/b168f105-720f-4f21-aba1-5be5c0326957)

## Install via pip

```
pip install knock-subdomains
```

## Install via pip requirements.txt file

```
knockpy @ git+https://github.com/guelfoweb/knock.git
```

## Install via git

```bash
git clone https://github.com/guelfoweb/knock.git
cd knock
pip install .
```

## Usage

```
usage: KNOCKPY [-h] [-d DOMAIN] [-f FILE] [-v] [--dns DNS] [--useragent USERAGENT]
               [--timeout TIMEOUT] [--threads THREADS] [--recon] [--bruteforce] 
               [--wordlist WORDLIST] [--json-output] [--list] [--report REPORT]

knockpy v.7.0.1 - Subdomain Scan
https://github.com/guelfoweb/knock

options:
  -h, --help            show this help message and exit
  -d DOMAIN, --domain DOMAIN
                        domain to analyze
  -f FILE, --file FILE  domain list from file path
  -v, --version         show program's version number and exit
  --dns DNS             custom dns
  --useragent USERAGENT
                        custom useragent
  --timeout TIMEOUT     custom timeout
  --threads THREADS     custom threads
  --recon               subdomain reconnaissance
  --bruteforce          subdomain bruteforce
  --wordlist WORDLIST   wordlist file to import
                        --bruteforce option required
  --wildcard            test wildcard and exit
  --json                shows output in json format
  --save FOLDER         folder to save report
  --report REPORT       shows saved report
```

### Example

- Start scanning domain with `--recon` and `--bruteforce` options

```bash
knockpy -d domain.com --recon --bruteforce
```

- Set API KEY: VirusTotal and Shodan

```bash
export API_KEY_VIRUSTOTAL=your-virustotal-api-key
export API_KEY_SHODAN=your-shodan-api-key
```

- Save the report in a folder

```bash
knockpy -d domain.com --recon --bruteforce --save report
```

- Shows saved report

```bash
knockpy --report domain.com_yyyy_aa_dd_hh_mm_ss.json
```

### Import as module

```python
from knock import KNOCKPY

domain = 'domain.com'

results = KNOCKPY(domain, dns=None, useragent=None, timeout=None, threads=None, recon=True, bruteforce=True, wordlist=None)

print (results)
```
