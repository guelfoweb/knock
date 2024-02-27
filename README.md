# Knock Subdomain Scan v7.0.0

:heavy_check_mark: Fast :heavy_check_mark: Easy :heavy_check_mark: Modular

## Install via pip

```
pip install git+https://github.com/guelfoweb/knock.git
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
usage: KNOCKPY [-h] [-d DOMAIN] [-f FILE] [-v] [--dns DNS] [--useragent USERAGENT] [--timeout TIMEOUT] [--threads THREADS]
               [--recon] [--bruteforce] [--wordlist WORDLIST] [--json-output] [--list] [--report REPORT]

knockpy v.7.0.0 - Subdomain Scan
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
  --json-output         shows output in json format
  --list                lists saved reports
  --report REPORT       shows saved report

```

### Example

- Start scanning domain with `--recon` and `--bruteforce` options

```bash
knockpy -d domain.com --recon --bruteforce
```

- Lists saved reports

```bash
knockpy --list
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