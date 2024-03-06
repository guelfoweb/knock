#!/usr/bin/env python3

from datetime import datetime, date
import concurrent.futures
import dns.resolver
import OpenSSL
import ssl
import requests
import argparse
import random
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

__version__ = '7.0.0'

ROOT = os.path.abspath(os.path.dirname(__file__))

# bruteforce via wordlist
class Bruteforce:
    def __init__(self, domain, wordlist=None):
            self.domain = domain
            self.wordlist = wordlist if wordlist else ROOT + os.sep + 'wordlist' + os.sep + 'wordlist.txt'

    def load_wordlist(self):
        return open(self.wordlist, 'r').read().split('\n')

    def start(self):
        wordlist = list(set([word+'.'+self.domain for word in Bruteforce.load_wordlist(self)]))
        return wordlist

# reconnaissance via web services
class Recon:
    def __init__(self, domain, timeout=None):
            self.domain = domain
            self.timeout = timeout if timeout else 5
    
    def req(self, url):
        try:
            resp = requests.get(url, self.timeout).text
            return resp
        except:
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
            ("webarchive", f"https://web.archive.org/cdx/search/cdx?url=*.{self.domain}/*&output=txt&fl=original&collapse=urlkey")
            ]
        return services_list

    def start(self):
        services_list = Recon.services(self)

        subdomains = []

        pbar = tqdm(range(len(services_list)), desc="Recon.....", leave=True, ncols=80)
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            results = {executor.submit(Recon.reconnaissance, self, service) for service in services_list}

            for item in concurrent.futures.as_completed(results):
                pbar.update(1)
                name, resp = item.result()
                if name == "alienvault":
                    try:
                        resp = json.loads(resp)
                        subdomains += [item['hostname'] for item in resp['passive_dns'] if item['hostname'].endswith(self.domain)]
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
                        
            subdomains = [s for s in list(set(subdomains)) if '*' not in s]

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
            return None, None
        
        # 0=v1, 1=v2, 2=v3
        #version = x509.get_version()
        #print (version)
        bytes = x509.get_notAfter()
        timestamp = bytes.decode('utf-8')
        
        # convert dateobj and datenow to isoformat and compare the values
        dateobj = datetime.strptime(timestamp, '%Y%m%d%H%M%S%z').date().isoformat()
        datenow = datetime.now().date().isoformat()
        is_good = False if dateobj < datenow else True

        if is_good:
            # looking for valid (CN) Common Name
            common_name = x509.get_subject().commonName
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

        return is_good, dateobj

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
            domain = http_redirect_location.split('://')[1]
            domain = domain.split('/')[0]
            results["domain"] = domain
            https_status_code, https_redirect_location, server_name = self.http_response(f"https://{domain}")
            results.update({"https": [https_status_code, https_redirect_location]})

        is_good, dateobj = None, None
        if https_status_code:
            is_good, dateobj = self.cert_status(results["domain"])
        
        results.update({"cert": [is_good, dateobj]})

        return results

def KNOCKPY(domain, dns=None, useragent=None, timeout=None, threads=None, recon=None, bruteforce=None, wordlist=None):
    def knockpy(domain, dns=None, useragent=None, timeout=None):
        return HttpStatus(domain, dns, useragent, timeout).scan()
    
    if recon and bruteforce:
        domain = Recon(domain, timeout).start()
        domain += Bruteforce(domain, wordlist).start()
        domain = list(set(domain))
    elif recon:
        domain = Recon(domain, timeout).start()
    elif bruteforce:
        domain = Bruteforce(domain, wordlist).start()

    if isinstance(domain, list):
        if not threads:
            threads = 10
        
        pbar = tqdm(range(len(domain)), desc="Processing", leave=True, ncols=80)
        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
            futures = [executor.submit(knockpy, d, dns, useragent, timeout) for d in domain]

            results = []
            for future in concurrent.futures.as_completed(futures):
                pbar.update(1)
                if future.result():
                    results.append(future.result())

        return results

    return knockpy(domain, dns=None, useragent=None, timeout=None)

def output(results, json_output=None):
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
    parser.add_argument("-d", "--domain", help="domain to analyze")
    parser.add_argument("-f", "--file", help="domain list from file path")
    parser.add_argument("-v", "--version", action="version", version="%(prog)s " + __version__)
    parser.add_argument("--dns", help="custom dns", dest="dns", required=False)
    parser.add_argument("--useragent", help="custom useragent", dest="useragent", required=False)
    parser.add_argument("--timeout", help="custom timeout", dest="timeout", type=float, required=False)
    parser.add_argument("--threads", help="custom threads", dest="threads", type=int, required=False)
    parser.add_argument("--recon", help="subdomain reconnaissance", action="store_true", required=False)
    parser.add_argument("--bruteforce", help="subdomain bruteforce", action="store_true", required=False)
    parser.add_argument("--wordlist", help="wordlist file to import\n--bruteforce option required", dest="wordlist", required=False)
    parser.add_argument('--json', help="shows output in json format", action="store_true", required=False)
    parser.add_argument("--save", help="folder to save report", dest="folder", required=False)
    parser.add_argument("--report", help="shows saved report", dest="report", required=False)
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
        if args.recon and args.bruteforce:
            domain = Recon(args.domain, args.timeout).start()
            domain += Bruteforce(args.domain, args.wordlist).start()
            domain = list(set(domain))
        elif args.recon:
            domain = Recon(args.domain, args.timeout).start()
        elif args.bruteforce:
            domain = Bruteforce(args.domain, args.wordlist).start()

        results = KNOCKPY(domain, args.dns, args.useragent, args.timeout)
        
        if args.recon or args.bruteforce:
            save(args.domain, results, args.folder)
        
        output(results, args.json)
    
    if args.file:
        with open(args.file,'r') as f:
            domains = f.read().splitlines()
        results = KNOCKPY(domains, args.dns, args.useragent, args.timeout)
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