# Knock Subdomain Scan v6.1.0

Knockpy is a portable and modular python3 tool designed to quickly enumerate subdomains on a target domain through **passive reconnaissance** and **dictionary scan**.

![knockpy6](https://user-images.githubusercontent.com/41558/212566603-3120aef5-7df0-402d-b80d-7ea8b14f8c73.png)

### Very simply
```bash
python3 knockpy.py domain.com
```

# Table of Contents
* [Install](#install)
    * [Run from folder](#run-from-folder)
    * [Install package](#install-package)
    * [Docker](#docker)
* [Usage](#usage)
    * [Full scan](#full-scan)
    * [Scan with remote list only](#scan-with-remote-list-only---no-local)
    * [No scan, get remote list only](#no-scan-get-remote-list-only---no-local---no-scan)
    * [Use a custom DNS](#use-a-custom-dns---dns)
    * [Silent mode](#silent-mode---silent)
    * [Output folder](#output-folder--o)
* [Report](#report)
    * [Show report](#show-report---report)
    * [Convert report in csv](#convert-report-in-csv---csv)
    * [Plot report](#plot-report---plot)
* [Module](#module)
* [Plugin](#plugin)
    * [Write your own plugin](#write-your-own-plugin)
    * [Plugin test](#plugin-test---plugin-test)
* [License](#license)

---

# Install

### Run from folder
###### You need python3, pip3, git.

```bash
git clone https://github.com/guelfoweb/knock.git
cd knock
pip3 install -r requirements.txt

python3 knockpy.py <DOMAIN>
```
### Install package
###### As root

```bash
git clone https://github.com/guelfoweb/knock.git
cd knock
python3 setup.py install

knockpy <DOMAIN>
````

### Docker

Knockpy image hosted at [DockerHub Page](https://hub.docker.com/r/secsi/knockpy) and automatically updated with [RAUDI](https://github.com/cybersecsi/RAUDI)

```
docker run -it --rm secsi/knockpy <domain>
```

---

# Usage

#### As a standalone command line tool

### Knockpy ```-h```

```
usage: knockpy [-h] [-v] [--no-local] [--no-remote] [--no-scan] [--no-http] 
               [--no-http-code CODE [CODE ...]] [--dns DNS] [-w WORDLIST] 
               [-o FOLDER] [-t SEC] [-th NUM] [--silent [{False,json,json-pretty,csv}]]
               domain

--------------------------------------------------------------------------------
* SCAN
full scan:    knockpy domain.com
quick scan:   knockpy domain.com --no-local
faster scan:  knockpy domain.com --no-local --no-http
ignore code:  knockpy domain.com --no-http-code 404 500 530
silent mode:  knockpy domain.com --silent

* SUBDOMAINS
show recon:   knockpy domain.com --no-local --no-scan

* REPORT
show report:  knockpy --report knockpy_report/domain.com_yyyy_mm_dd_hh_mm_ss.json
plot report:  knockpy --plot knockpy_report/domain.com_yyyy_mm_dd_hh_mm_ss.json
csv report:   knockpy --csv knockpy_report/domain.com_yyyy_mm_dd_hh_mm_ss.json
--------------------------------------------------------------------------------

positional arguments:
  domain                target to scan

optional arguments:
  -h, --help            show this help message and exit
  -v, --version         show program's version number and exit
  --no-local            local wordlist ignore
  --no-remote           remote wordlist ignore
  --no-scan             scanning ignore, show wordlist and exit
  --no-http             http requests ignore
                        
  --no-http-code CODE [CODE ...]
                        http code list to ignore

  --dns DNS             use custom DNS ex. 8.8.8.8                        

  -w WORDLIST           wordlist file to import
  -o FOLDER             report folder to store json results
  -t SEC                timeout in seconds
  -th NUM               threads num

  --silent [{False,json,json-pretty,csv}]
                        silent or quiet mode, default: False
```

---

### Full scan
```bash
$ knockpy domain.com
```

- Scan type: **dns** + **http(s)** requests
- Wordlist: **local** + **remote**

Knockpy uses by default a internal file **wordlist.txt** and a remote list obtained by scanning other sources (passive recon) through **plugins**. To use a custom dictionary you can use the ```-w``` option and specify the path to your local dictionary. Also, you can write a new plugin to populate the wordlist with subdomains obtained from external services. Take a look at the ones in the [remote](knockpy/remote) folder and use them as an example. Remember that some plugins, like [Virustotal](knockpy/remote/api_virustotal.py) or [Shodan](knockpy/remote/api_shodan.py), need apikey to work.

The domain target can be passed via STDIN.

```bash
echo "domain.com" | knockpy
```

To ignore http(s) responses with specific code, you can use the ```--no-http-code``` followed by the code list ```404 500 530```. With the ```--no-ip``` option you can ignore ip list ```192.168.1.100 192.168.101 192.168.1.102```

---

### Scan with remote list only: ```--no-local```
```bash
$ knockpy domain.com --no-local
```

- Scan type: **dns** + **http(s)** requests
- Wordlist: **remote**

Only test subdomains obtained through **passive reconnaissance** using plugins. This scanning mode will be faster because it excludes the local dictionary.

---

### No scan, get remote list only: ```--no-local --no-scan```
```bash
$ knockpy domain.com --no-scan --no-local
```

- Scan type: **none**
- Wordlist: **remote list**

Print passive-only wordlist and exit. No scan will be performed.

---

### Use a custom DNS: ```--dns```
```bash
$ knockpy domain.com --dns 8.8.8.8
```

By default it uses the pre-configured DNS on your system (ex. ```/etc/resolv.conf```).

---

### Silent mode: ```--silent```
```bash
$ knockpy domain.com --silent
```

Hide terminal output and save **json** report in the output folder. Using ```--silent``` with the ```--no-scan``` option hides the banner and shows the **list** of subdomains to the terminal.

```bash
$ knockpy domain.com --silent json
```

Hide terminal output and print final results in **json** format.

```bash
$ knockpy domain.com --silent json-pretty
```

Hide terminal output and print final results in **intented json**.

```bash
$ knockpy domain.com --silent csv
```

Hide terminal output and print final results in **csv** format.

**Note** that at each scan the report will be [automatically saved](#report).

---

### Output folder: ```-o```
```bash
$ knockpy domain.com -o /path/to/new/folder
```

All scans are saved in the default folder ```knockpy_report```. Alternatively, you can use the ```-o /path/folder``` to define the new folder path or disable autosave using ```-o false```.

---

# Report
At each scan the report will be automatically saved in **json** format inside the file with the name ```domain.com_yyyy_mm_dd_hh_mm_ss.json```. If you don't like autosave you can disable using ```-o false```.

Report example ```domain.com_yyyy_mm_dd_hh_mm_ss.json```:

```
{
    "sub-1.domain.com": {
        "domain": "host.domain.ext",
        "alias": ["sub-1.domain.com"],
        "ipaddr": [
            "123.123.123.123"
        ],
        "code": 200,
        "server": "Microsoft-IIS/8.5"
    },
    ...................................
               -- cut --
    ...................................
    "sub-n.domain.com"{
        "domain": "",
        "alias": [],
        "ipaddr": [
            "123.123.123.124"
        ],
        "code": 500,
        "server": "nginx/1.15.6 "
    },
    "_meta": {
        "name": "knockpy",
        "version": "5.4.1",
        "time_start": 1616353591.2510355,
        "time_end": 1616353930.6632543,
        "domain": "domain.com",
        "wordlist": 2120
    }
}
```
```_meta``` is a reserved key that contains the basic information of the scan.

---

### Show report: ```--report```
```bash
$ knockpy --report knockpy_report/domain.com_yyyy_mm_dd_hh_mm_ss.json
```

Print the report in the terminal in a human format.

---

### Convert report in CSV: ```--csv```
```bash
$ knockpy --csv knockpy_report/domain.com_yyyy_mm_dd_hh_mm_ss.json
```

Save the existing report in csv file.

---

### Plot report: ```--plot```
```bash
$ knockpy --plot knockpy_report/domain.com_yyyy_mm_dd_hh_mm_ss.json
```

- Plot relationships.

Plot needs these libraries: 
- matplotlib
- networkx
- PyQt5

![facebook](https://user-images.githubusercontent.com/41558/113183466-5a9bcc00-9254-11eb-8d9f-6a9c239eea7d.png)

---

# Module

#### Usage as a library

Importing knockpy as a module (dependence) in your python script is quite simple. Naturally, the package [must be installed](#install-package) on your system.

```python
from knockpy import knockpy
```
The command-line parameters can be managed with the following dictionary.

```python
params = {
    "no_local": False,  # [bool] local wordlist ignore
    "no_remote": False, # [bool] remote wordlist ignore
    "no_scan": False,   # [bool] scanning ignore, show wordlist
    "no_http": False,   # [bool] http requests ignore
    "no_http_code": [], # [list] http code list to ignore
    "no_ip": [],        # [list] ip address to ignore
    "dns": "",          # [str] use custom DNS ex. 8.8.8.8
    "timeout": 3,       # [int] timeout in seconds
    "threads": 30,      # [int] threads num
    "useragent": "",    # [str] use a custom user agent
    "wordlist": ""      # [str] path to custom wordlist
}
```
You can choose pass only the keys you want to change and keep the others with the default values. Eg:

```python
params = {
    "no_local": True,
    "no_scan": True
}
```
Then you can call the function ```knockpy.Scanning.start()``` passing as values the **domain** and the dictionary assigned to the variable **params** to get the results in **json** format. 

```python
results = knockpy.Scanning.start("domain.com", params)
```

---

# Plugin

### Write your own plugin

The plugins are situated in ```remote``` folder. If you want to write your own plugin it's important to pay attention to some precautions:

- if apikey is required, use ```api_``` before the plugin name:
```
    api_service.py
```
- the function name must be ```get``` and take as parameter ```domain```:
```python
    def get(domain):
        foo
```
- the function must return a possibly unique list of subdomains:
```
    ['sub1.domain.com', 'sub2.domain.com', ...]
```
- to parse/scrape the results it is recommended to use the standard modules such as:
```python
    requests, json, bs4, re
```

Here is an **example** of how a plugin should be structured. You can find other examples in the [remote](knockpy/remote) folder.

```python
import requests
import json

def get(domain):
    # servicename -> JSON: key -> subdomain
    url = "https://servicename.com/search/?q={domain}".format(domain=domain)
    resp = requests.get(url, timeout=5).text
    
    resp = json.loads(resp)
    
    result = []
    for item in resp['data']:
        subdomain = item['subdomain']
        if subdomain not in result:
            result.append(subdomain)

    return result
```

### Plugin test ```--plugin-test```

```bash
$ knockpy domain.com --plugin-test
```

In this example, the output shows errors ```'error': True``` in three plugins because they need the API key.

```bash
{
    'api_shodan.py': {
        'time': '00:00:03',
        'match': 0,
        'error': True
    },
    'certspotter.py': {
        'time': '00:00:00',
        'match': 9,
        'error': False
    },
    'rapiddns.py': {
        'time': '00:00:00',
        'match': 44,
        'error': False
    },
    'hackertarget.py': {
        'time': '00:00:00',
        'match': 9,
        'error': False
    },
    'crtsh.py': {
        'time': '00:00:19',
        'match': 10,
        'error': False
    },
    'api_censys.py': {
        'time': '00:00:03',
        'match': 0,
        'error': True
    },
    'webarchive.py': {
        'time': '00:00:04',
        'match': 4,
        'error': False
    },
    'api_virustotal.py': {
        'time': '00:00:03',
        'match': 0,
        'error': True
    },
    'alienvault.py': {
        'time': '00:00:01',
        'match': 11,
        'error': False
    },
    '_results': {
        'time': '00:00:37',
        'plugins': {
            'count': 9,
            'list': ['api_shodan.py', 'certspotter.py', 'rapiddns.py', 'hackertarget.py', ...],
            'error': ['api_shodan.py', 'api_censys.py', 'api_virustotal.py']
        },
        'subdomains': {
            'count': 52,
            'list': ['admin', 'cloud', 'www', 'mail', 'calendar', 'contact', 'ftp', .....]
        }
    }
}

```
---

# License
Knockpy is currently under development by [@guelfoweb](https://twitter.com/guelfoweb) and it's released under the GPL 3 license.
