#!/usr/bin/env python3

from datetime import datetime, date
from collections import OrderedDict
import concurrent.futures
import dns.resolver
import OpenSSL
import ssl
import requests
from typing import Optional, Union
import argparse
import random
import string
import json
import bs4
import sys
import os
import re
from tqdm.auto import tqdm
import warnings
from urllib3.exceptions import InsecureRequestWarning

# Suppress the warnings from urllib3
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

__version__ = '7.0.2'

ROOT = os.path.abspath(os.path.dirname(__file__))

# bruteforce via wordlist
class Bruteforce:
    def __init__(self, domain, wordlist=None):
            self.domain = domain
            self.wordlist = wordlist or os.path.join(ROOT, 'wordlist', 'wordlist.txt')

    def load_wordlist(self):
        try:
            with open(self.wordlist, 'r') as f:
                return [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            print(f"Error: wordlist '{self.wordlist}' not found.")
            return []

    def wildcard(self):
        return ''.join(random.choice(string.ascii_lowercase) for _ in range(random.randint(10, 15))) + '.' + self.domain

    def start(self):
        wordlist = [str(word)+'.'+str(self.domain) for word in Bruteforce.load_wordlist(self) if word]
        wordlist = list(OrderedDict.fromkeys(wordlist))
        return wordlist

# reconnaissance via web services
class Recon:
    def __init__(self, domain: str, timeout: Optional[int] = 3, silent: Optional[bool] = None):
        """
        Initializes the Recon class.

        :param domain: The domain to analyze.
        :param timeout: Timeout for requests in seconds (default: 3).
        :param silent: If True, suppresses error messages (default: None).
        """
        self.domain = domain
        self.timeout = timeout
        self.silent = silent

    def req(self, url: str) -> Union[str, None]:
        """
        Makes a GET request to the specified URL.

        :param url: The URL to request.
        :return: The content of the response if the request is successful, otherwise [].
        """
        try:
            resp = requests.get(url, timeout=(self.timeout, self.timeout))
            resp.raise_for_status()  # Raise an exception for HTTP status codes 4xx/5xx
            return resp.text
        except requests.exceptions.Timeout:
            if not self.silent:
                print(f"Request to {url} timed out.")
            return []
        except requests.exceptions.RequestException as e:
            if not self.silent:
                print(f"An error occurred: {e}")
            return []

    def reconnaissance(self, service):
        name, url = service
        resp = Recon.req(self, url)
        return name, resp

    def services(self):
        services_list = [
            ("alienvault", f"https://otx.alienvault.com/api/v1/indicators/domain/{self.domain}/passive_dns"),
            ("certspotter", f"https://api.certspotter.com/v1/issuances?domain={self.domain}&include_subdomains=true&expand=dns_names"),
            ("crtsh", f"https://crt.sh/?q={self.domain}&output=json"),
            ("hackertarget", f"https://api.hackertarget.com/hostsearch/?q={self.domain}"),
            ("rapiddns", f"https://rapiddns.io/subdomain/{self.domain}"),
            ("webarchive", f"https://web.archive.org/cdx/search/cdx?url=*.{self.domain}/*&output=txt")
            ]

        API_KEY_VIRUSTOTAL = os.getenv("API_KEY_VIRUSTOTAL")
        if API_KEY_VIRUSTOTAL:
            services_list.append(("virustotal", f"https://www.virustotal.com/vtapi/v2/domain/report?apikey={API_KEY_VIRUSTOTAL}&domain={self.domain}"))

        API_KEY_SHODAN = os.getenv("API_KEY_SHODAN")
        if API_KEY_SHODAN:
            services_list.append(("shodan", f"https://api.shodan.io/dns/domain/{self.domain}?key={API_KEY_SHODAN}"))

        return services_list

    def start(self):
        services_list = Recon.services(self)

        subdomains = []

        if not self.silent:
            pbar = tqdm(range(len(services_list)), desc="Recon.....", leave=True, ncols=80)

        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            results = {executor.submit(Recon.reconnaissance, self, service): service for service in services_list}

            for future in concurrent.futures.as_completed(results):
                if not self.silent:
                    pbar.update(1)
                try:
                    name, resp = future.result()
                    # Process the response as before...
                except Exception as e:
                    if not self.silent:
                        print(f"Error processing service {results[future]}: {e}")

                if name == "alienvault":
                    try:
                        resp = json.loads(resp)
                        subdomains += [item['hostname'] for item in resp['passive_dns'] if item['hostname'].endswith(self.domain)]
                    except:
                        pass
                elif name == "virustotal":
                    try:
                        resp = json.loads(resp)
                        if "subdomains" in resp.keys():
                            for subdomain in resp["subdomains"]:
                                if subdomain.endswith(self.domain):
                                    subdomains.append(subdomain)
                    except:
                        pass
                elif name == "shodan":
                    try:
                        resp = json.loads(resp)
                        if "subdomains" in resp.keys():
                            for subdomain in resp["subdomains"]:
                                subdomain = subdomain+"."+self.domain
                                subdomains.append(subdomain)
                    except:
                        pass
                elif name == "certspotter":
                    try:
                        resp = json.loads(resp)
                        for item in resp:
                            for subdomain in item['dns_names']:
                                if subdomain.endswith(self.domain):
                                    subdomains.append(subdomain)
                    except:
                        pass
                elif name == "crtsh":
                    try:
                        resp = json.loads(resp)
                        subdomains += [item['common_name'] for item in resp if item['common_name'].endswith(self.domain)]
                    except:
                        pass
                elif name == "hackertarget":
                    try:
                        subdomains += [item.split(',')[0] for item in resp.split('\n') if item.split(',')[0]]
                    except:
                        pass
                elif name == "rapiddns":
                    try:
                        soup = bs4.BeautifulSoup(resp, "html.parser")
                        subdomains += [item.text for item in soup.find_all("td") if item.text.endswith(self.domain)]
                    except:
                        pass            
                elif name == "webarchive":
                    try:
                        pattern = r"http(s)?:\/\/(.*\.%s)" % self.domain
                        for item in resp.split('\n'):
                            match = re.match(pattern, item)
                            if match and re.match(r"^[a-zA-Z0-9-\.]*$", match.groups()[1]):
                                subdomains += [item for item in match.groups()[1] if item.endswith(self.domain)]
                    except:
                        pass
                        
            subdomains = [s for s in list(OrderedDict.fromkeys(subdomains)) if '*' not in s]

        return sorted(subdomains)

# List of user agents for HTTP requests
user_agent = [
    'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:33.0) Gecko/20120101 Firefox/33.0',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10; rv:33.0) Gecko/20100101 Firefox/33.0',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_3) AppleWebKit/537.75.14 (KHTML, like Gecko) Version/7.0.3 Safari/7046A194A',
    'Mozilla/5.0 (MSIE 10.0; Windows NT 6.1; Trident/5.0)',
]

# test domains via DNS, HTTP, HTTPS and Certificate
class HttpStatus:
    def __init__(self, domain, dns=None, useragent=None, timeout=None):
        self.domain = domain
        self.dns = dns if dns else '8.8.8.8'
        self.headers = {'User-Agent': random.choice(user_agent)} if not useragent else {'User-Agent': useragent}
        self.timeout = timeout if timeout else 0.5

    def http_response(self, url):
        try:
            response = requests.get(url, headers=self.headers, allow_redirects=False, timeout=self.timeout, verify=False)
        except requests.RequestException as e:
            #print (str(e))
            """
            # verify=False disable security certificate checks
            # so, this exception is not used
            #
            # certificate error or expired
            if 'CERTIFICATE_VERIFY_FAILED' in str(e):
                # {"https": [200, null, null]}
                return 200, None, None
            """
            return None, None, None
        
        #headers_response = response.headers
        #http_version = response.raw.version
        status_code = response.status_code
        redirect_location = response.headers.get('Location')
        server_name = response.headers.get('Server')

        return status_code, redirect_location, server_name

    def cert_status(self, domain):
        try:
            cert = ssl.get_server_certificate((domain, 443))
            x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
        except Exception as e:
            #print(f"Error connecting to {self.domain}: {e}")
            return None, None, None
        
        # 0=v1, 1=v2, 2=v3
        #version = x509.get_version()
        #print (version)
        bytes = x509.get_notAfter()
        timestamp = bytes.decode('utf-8')
        
        # convert dateobj and datenow to isoformat and compare the values
        dateobj = datetime.strptime(timestamp, '%Y%m%d%H%M%S%z').date().isoformat()
        datenow = datetime.now().date().isoformat()
        is_good = False if dateobj < datenow else True
        common_name = None

        if is_good:
            # looking for valid (CN) Common Name
            common_name = x509.get_subject().commonName
            #print (common_name)
            for i in range(x509.get_extension_count()):
                ext = x509.get_extension(i)
                if "subjectAltName" in str(ext.get_short_name()):
                    # ['DNS:domain.it', 'DNS:www.domain.it', 'DNS:sub.domain.domain.it']
                    cn = str(ext).replace("DNS:", "").split(", ")
                    if domain not in cn:
                        for name in cn:
                            # the domain use wildcard
                            # ['DNS:domain.it', 'DNS:www.domain.it', 'DNS:*.domain.domain.it']
                            if '*.' in name:
                                name = name.replace("*.", "")
                                if name in domain:
                                    break
                                is_good = False

        return is_good, dateobj, common_name

    def domain_resolver(self):
        res = dns.resolver.Resolver()
        res.timeout = self.timeout
        res.lifetime = self.timeout
        res.nameservers = [self.dns]

        try:
            ipv4 = res.resolve(self.domain, 'A')
        except:
            return None

        return [str(ip) for ip in ipv4]

    def scan(self):
        results = {"domain": self.domain}
        ip_list = self.domain_resolver()
        if not ip_list:
            return None
        
        # resolver
        results.update({"ip": ip_list})
        
        # http
        http_status_code, http_redirect_location, server_name = self.http_response(f"http://{self.domain}")
        results.update({"http": [http_status_code, http_redirect_location, server_name]})
        
        # https
        https_status_code, https_redirect_location, server_name = self.http_response(f"https://{self.domain}")
        results.update({"https": [https_status_code, https_redirect_location, server_name]})

        # https exception error
        if http_status_code and http_redirect_location and not https_status_code:
            if not http_redirect_location.startswith(('http://', 'https://')):
                http_redirect_location = 'http://' + http_redirect_location
            
            domain = http_redirect_location.split('://')[1]
            domain = domain.split('/')[0]
            https_status_code, https_redirect_location, server_name = self.http_response(f"https://{domain}")
            results.update({"https": [https_status_code, https_redirect_location, server_name]})

        is_good, dateobj, common_name = None, None, None
        if https_status_code:
            is_good, dateobj, common_name = self.cert_status(results["domain"])
        
        results.update({"cert": [is_good, dateobj, common_name]})

        return results

def KNOCKPY(domain, dns=None, useragent=None, timeout=None, threads=None, recon=None, bruteforce=None, wordlist=None, silent=None):
    def knockpy(domain, dns=None, useragent=None, timeout=None):
        return HttpStatus(domain, dns, useragent, timeout).scan()
    
    if recon and bruteforce:
        domain = Recon(domain, timeout, silent).start()
        domain += Bruteforce(domain, wordlist).start()
        domain = list(OrderedDict.fromkeys(domain))
    elif recon:
        domain = Recon(domain, timeout, silent).start()
    elif bruteforce:
        domain = Bruteforce(domain, wordlist).start()

    if isinstance(domain, list):
        if not threads:
            threads = min(30, len(domain))
        
        if not silent:
            pbar = tqdm(range(len(domain)), desc="Processing", leave=True, ncols=80)
        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
            futures = [executor.submit(knockpy, d, dns, useragent, timeout) for d in domain]

            results = []
            for future in concurrent.futures.as_completed(futures):
                if not silent:
                    pbar.update(1)
                if future.result():
                    results.append(future.result())

        return results

    return knockpy(domain, dns=None, useragent=None, timeout=None)

def output(results, json_output=None):
    if not results:
        return None

    if json_output:
        print (results)
        sys.exit()

    if isinstance(results, dict):
        results = [results]

    # colors
    RED = '\033[1;31m'
    MAGENTA = '\033[1;35m'
    YELLOW = '\033[1;33m'
    CYAN = '\033[1;36m'
    END = '\033[0m' # reset

    for item in results:
        status_ok = True
        if item['http'][0] != 200:
            http = 'http '
        else:
            http = YELLOW + 'http ' + END
            status_ok = False
        if item['cert'][0] != False:
            cert = 'cert '
        else:
            cert = YELLOW + 'cert ' + END
            status_ok = False

        if status_ok:
            if all(i is None for i in item['http']) and all(i is None for i in item['https']):
                print (MAGENTA + item['domain'] + END, item['ip'])
            else:
                print (CYAN + item['domain'] + END, item['ip'])
        else:
            print (RED + item['domain'] + END, item['ip'])
        
        print (http, item['http'])
        print ('https', item['https'])
        print (cert, item['cert'])
        print ()

    print (len(results), 'domains')

def save(domain, results, folder):
    dt = str(datetime.now()).replace("-", "_").replace(" ", "_").replace(":", "_").split('.')[0]
    if not folder:
        path = domain + '_' + dt + '.json'
    else:
        if not os.path.exists(folder):
            os.makedirs(folder)
        path = folder + os.sep + domain + '_' + dt + '.json'
    
    f = open(path, "w")
    f.write(json.dumps(results, indent=4))
    f.close()

def show_report(json_output, report_name):
    with open(report_name) as f:
        report = json.loads(f.read())
    output(report, json_output)

def main():
    parser = argparse.ArgumentParser(
        prog="KNOCKPY", 
        description=f"knockpy v.{__version__} - Subdomain Scan\nhttps://github.com/guelfoweb/knock", 
        formatter_class=argparse.RawTextHelpFormatter
        )

    # args
    parser.add_argument("-d", "--domain", help="Domain to analyze.")
    parser.add_argument("-f", "--file", help="Path to a file containing a list of domains.")
    parser.add_argument("-v", "--version", action="version", version="%(prog)s " + __version__)
    parser.add_argument("--dns", help="Custom DNS server.", dest="dns", required=False)
    parser.add_argument("--useragent", help="Custom User-Agent string.", dest="useragent", required=False)
    parser.add_argument("--timeout", help="Custom timeout in seconds.", dest="timeout", type=float, required=False)
    parser.add_argument("--threads", help="Number of threads to use.", dest="threads", type=int, required=False)
    parser.add_argument("--recon", help="Enable subdomain reconnaissance.", action="store_true", required=False)
    parser.add_argument("--bruteforce", help="Enable subdomain brute-forcing.", action="store_true", required=False)
    parser.add_argument("--wordlist", help="Path to a wordlist file (required for --bruteforce).", dest="wordlist", required=False)
    parser.add_argument('--wildcard', help="Test for wildcard DNS and exit.", action="store_true", required=False)
    parser.add_argument('--json', help="Output results in JSON format.", action="store_true", required=False)
    parser.add_argument("--save", help="Directory to save the report.", dest="folder", required=False)
    parser.add_argument("--report", help="Display a saved report.", dest="report", required=False)
    parser.add_argument("--silent", help="Suppress progress bar output.", action="store_true", required=False)
    args = parser.parse_args()

    #print (args)
    
    if not args.domain and not args.file:
        # looking for stdin
        if not sys.stdin.isatty():
            stdin = [domain.strip() for domain in sys.stdin.readlines()]
            # can be file or domain
            if len(stdin) == 1:
                # check if is file
                # echo "/path/to/domains.txt" | knockpy
                if os.path.isfile(stdin[0]):
                    args.file = stdin[0]
                # otherwise domain is passed
                # echo "domain.com" | knockpy
                else:
                    args.domain = stdin[0]
            # domains list via file
            # cat domains.txt | knockpy
            elif len(stdin) > 1:
                args.domain = stdin
        elif args.report:
            show_report(args.json, args.report)
            sys.exit(0)
        # no args and not stdin
        # shows help and exit
        else:
            parser.print_help(sys.stderr)
            sys.exit(0)

    if args.domain:
        domain = args.domain
        if args.wildcard:
            domain = Bruteforce(domain).wildcard()
            results = KNOCKPY(domain, args.dns, args.useragent, args.timeout, args.silent)
            output(results, args.json)
            sys.exit(0)

        if args.recon and args.bruteforce:
            #print ("bruteforce", args.wordlist)
            domain = Recon(args.domain, args.timeout, args.silent).start()
            domain += Bruteforce(args.domain, args.wordlist).start()
            domain = list(OrderedDict.fromkeys(domain))
        elif args.recon:
            domain = Recon(args.domain, args.timeout, args.silent).start()
        elif args.bruteforce:
            domain = Bruteforce(args.domain, args.wordlist).start()

        results = KNOCKPY(domain, args.dns, args.useragent, args.timeout, args.silent)
        
        if args.recon or args.bruteforce:
            save(args.domain, results, args.folder)
        
        output(results, args.json)
    
    if args.file:
        with open(args.file,'r') as f:
            domains = f.read().splitlines()
        results = KNOCKPY(domains, args.dns, args.useragent, args.timeout, args.silent)
        output(results, args.json)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nInterrupted")
        try:
            sys.exit(0)
        except SystemExit:
            os._exit(0)