# Knock Subdomain Scan v5.3.0

Knockpy is a python3 tool designed to quickly enumerate subdomains on a target domain through dictionary attack.

![knockpy5](https://user-images.githubusercontent.com/41558/111915750-1bad8f80-8a78-11eb-951a-d5da1adc2bdc.png)

### Very simply
```python3 knockpy.py domain.com```

# Install

###### You need python3, pip3, git.

```
git clone https://github.com/guelfoweb/knock.git
cd knock
pip3 install -r requirements.txt
python3 knockpy.py <DOMAIN>
```

# Knockpy -h

```
usage: knockpy [-h] [-v] [--no-local] [--no-remote] [--no-http] [--no-http-code CODE [CODE ...]] 
               [-w WORDLIST] [-o FOLDER] [-t SEC] [-th NUM] domain

--------------------------------------------------------------------------------
* SCAN
full scan:    knockpy domain.com
ignore code:  knockpy domain.com --no-http-code 404 500 530
threads:      knockpy domain.com -th 50
timeout:      knockpy domain.com -t 2

* REPORT
show report:  knockpy --report knockpy_report/domain.com_yyyy_mm_dd_hh_mm_ss.json
plot report:  knockpy --plot knockpy_report/domain.com_yyyy_mm_dd_hh_mm_ss.json
csv report:   knockpy --csv knockpy_report/domain.com_yyyy_mm_dd_hh_mm_ss.json

* SETTINGS
set apikey:   knockpy --set apikey-virustotal=APIKEY
set timeout:  knockpy --set timeout=sec
set threads:  knockpy --set threads=num
--------------------------------------------------------------------------------

positional arguments:
  domain                target to scan

optional arguments:
  -h, --help            show this help message and exit
  -v, --version         show program's version number and exit
  --no-local            local wordlist ignore
  --no-remote           remote wordlist ignore
  --no-http             http requests ignore
                        
  --no-http-code CODE [CODE ...]
                        http code list to ignore

  --dns DNS             use custom DNS ex. 8.8.8.8                        

  -w WORDLIST           wordlist file to import
  -o FOLDER             report folder to store json results
  -t SEC                timeout in seconds
  -th NUM               threads num

```

# Usage

### Full scan
```$ knockpy domain.com```

- Attack type: **dns** + **http(s)** requests
- Knockpy uses internal file ```wordlist.txt```. If you want to use an external dictionary you can use the ```-w``` option and specify the path to your dictionary text file.
- Knockpy also tries to get subdomains from ```google```, ```duckduckgo```, and ```virustotal```. The results will be added to the general dictionary.
- It is highly recommended to use a [virustotal](https://github.com/guelfoweb/knock#virustotal-apikey) ```API_KEY``` which you can get for free. The best results always come from ```virustotal```.
- But, if you only want to work with local word lists, without search engines queries, you can add ```--no-remote``` to bypass remote recon.
- If you want to ignore http(s) responses with specific code, you can use the ```--no-http-code``` option followed by the code list ```404 500 530```

### Fast scan
```$ knockpy domain.com --no-http```

- Attack type: **dns**
- DNS requests only, no http(s) requests will be made. This way the response will be much faster and you will get the IP address and the Subdomain.
- The subdomain will be cyan in color if it is an ```alias``` and in that case the real host name will also be provided.

### Custom DNS
```$ knockpy domain.com --dns 8.8.8.8```

- by default it uses the pre-configured DNS on your system (ex. /etc/resolv.conf).

### Set threads
```$ knockpy domain.com -th 50```

- default threads = ```30```

### Set timeout
```$ knockpy domain.com -t 5```

- default timeout = ```3``` seconds.

### Virustotal APIKEY
```$ knockpy --set apikey-virustotal=APIKEY```

- Get [virustotal](https://virustotal.com/) ```APIKEY``` for free.

### Show report
```$ knockpy --report knockpy_report/domain.com_yyyy_mm_dd_hh_mm_ss.json```
- Show the report in the terminal.

### Csv report
```$ knockpy --csv knockpy_report/domain.com_yyyy_mm_dd_hh_mm_ss.json```
- Save report as csv file.

### Plot report
```$ knockpy --plot knockpy_report/domain.com_yyyy_mm_dd_hh_mm_ss.json```
- Plot relationships.

![facebook](https://user-images.githubusercontent.com/41558/113183466-5a9bcc00-9254-11eb-8d9f-6a9c239eea7d.png)

### Output folder
```$ knockpy domain.com -o /path/to/new/folder```

- All scans are saved in the default folder ```knockpy_report``` that you can edit in the ```config.json``` file. 
- Alternatively, you can use the ```-o``` option to define the new folder path.

### Report
- At each scan the report will be automatically saved in ```json``` format inside the file with the name ```domain.com_yyyy_mm_dd_hh_mm_ss.json```.
- If you don't like autosave you can disable it from the ```config.json``` file by changing the value to ```"save": false```.
- To read the report in a human format you can do as described in [Show report](https://github.com/guelfoweb/knock#show-report).

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
        "version": "5.1.0",
        "time_start": 1616353591.2510355,
        "time_end": 1616353930.6632543,
        "domain": "domain.com",
        "wordlist": 2120
    }
}
```

```_meta``` is a reserved key that contains the basic information of the scan.

# License

Knockpy is currently under development by [@guelfoweb](https://twitter.com/guelfoweb) and it's released under the GPL 3 license.
