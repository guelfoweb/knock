#!/usr/bin/env python3
"""
KnockPy - subdomain scan.
https://github.com/guelfoweb/knock
Gianni 'guelfoweb' Amato
"""

from __future__ import annotations
import os, sys, re, json, socket, ssl, argparse, logging
from datetime import datetime, timedelta
from collections import OrderedDict
from typing import List, Optional, Union, Iterable, Tuple, Dict, Any
import asyncio
import random
import string
import functools
import httpx
import bs4
import dns.resolver     # fallback resolver (sync)
import OpenSSL
from dotenv import load_dotenv
load_dotenv()

__version__ = "8.0.0"

ROOT = os.path.abspath(os.path.dirname(__file__))

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:33.0) Gecko/20120101 Firefox/33.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10; rv:33.0) Gecko/20100101 Firefox/33.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_3) AppleWebKit/537.75.14 (KHTML, like Gecko) Version/7.0.3 Safari/7046A194A",
    "Mozilla/5.0 (MSIE 10.0; Windows NT 6.1; Trident/5.0)",
]

# ---------------------------
# Logging
# ---------------------------

# Simple logger used by the tool.
# Level INFO by default. Use --logfile to write debug logs to a file.
logger = logging.getLogger("knockpy")
logger.setLevel(logging.INFO)
handler = logging.StreamHandler(sys.stderr)
handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s", "%H:%M:%S"))
logger.addHandler(handler)


# ---------------------------
# Elapsed time
# ---------------------------

# fmt_td:
# - Format time elapsed in hours, minutes, seconds.
def fmt_td(td: Optional[timedelta]) -> str:
    """Format a timedelta as HH:MM:SS, return '-' if None."""
    if td is None:
        return "-"
    total_seconds = int(td.total_seconds())
    hours, rem = divmod(total_seconds, 3600)
    minutes, seconds = divmod(rem, 60)
    return f"{hours:02d}:{minutes:02d}:{seconds:02d}"

# ---------------------------
# Bruteforce
# ---------------------------

# Bruteforce class:
# - Load words from a file.
# - Make subdomains by joining each word with the root domain.
# - It also can create a random wildcard test subdomain.
#
# Example:
#   b = Bruteforce("example.com")
#   list = b.start()    # ["www.example.com", "mail.example.com", ...]
class Bruteforce:
    """Simple wordlist-based bruteforcer."""
    def __init__(self, domain: str, wordlist: Optional[str] = None):
        self.domain = domain
        self.wordlist = wordlist or os.path.join(ROOT, "wordlist", "wordlist.txt")

    # load wordlist lines; return list of words
    # Example: ["www", "mail", "api"]
    def load(self) -> List[str]:
        try:
            with open(self.wordlist, "r", encoding="utf-8", errors="ignore") as fh:
                return [ln.strip() for ln in fh if ln.strip()]
        except FileNotFoundError:
            logger.error("Wordlist not found: %s", self.wordlist)
            return []

    # create a random subdomain for wildcard test
    # Example: "xkqzabc.example.com"
    def wildcard(self) -> str:
        rnd = "".join(random.choice(string.ascii_lowercase) for _ in range(random.randint(10, 15)))
        return f"{rnd}.{self.domain}"

    # Build full FQDN list from words and deduplicate preserving order
    # Example: ["www.example.com", "mail.example.com"]
    def start(self) -> List[str]:
        words = self.load()
        return list(OrderedDict.fromkeys(f"{w}.{self.domain}" for w in words if w))

# ---------------------------
# Recon (async)
# ---------------------------

# Recon class:
# - Define a set of external services (crt.sh, certspotter, AlienVault, etc.).
# - Query them in parallel and parse returned subdomains.
# - It returns a sorted unique list of discovered subdomains.
#
# Example:
#   r = Recon("example.com")
#   subs = await r.start()
#   # subs -> ["sub.example.com", "x.example.com"]
class Recon:
    """Query a set of web services asynchronously to collect subdomains."""
    def __init__(self, domain: str, timeout: float = 3.0, silent: bool = False, max_concurrency: int = 10):
        self.domain = domain
        self.timeout = timeout
        self.silent = silent
        self.max_concurrency = max_concurrency
        self.headers = {"User-Agent": random.choice(USER_AGENTS)}
        # read optional env API keys
        self.vt_key = os.getenv("API_KEY_VIRUSTOTAL")
        self.shodan_key = os.getenv("API_KEY_SHODAN")
        if not silent:
            print(f"- VirusTotal: {'✔️' if self.vt_key else '❌'}")
            print(f"- Shodan:     {'✔️' if self.shodan_key else '❌'}")

    # Build the service list. If env keys are present, add VT and Shodan.
    # Example return: [("crtsh", "https://crt.sh/?q=example.com&output=json"), ...]
    def services(self) -> List[Tuple[str, str]]:
        s = [
            ("alienvault", f"https://otx.alienvault.com/api/v1/indicators/domain/{self.domain}/passive_dns"),
            ("certspotter", f"https://api.certspotter.com/v1/issuances?domain={self.domain}&include_subdomains=true&expand=dns_names"),
            ("crtsh", f"https://crt.sh/?q={self.domain}&output=json"),
            ("hackertarget", f"https://api.hackertarget.com/hostsearch/?q={self.domain}"),
            ("rapiddns", f"https://rapiddns.io/subdomain/{self.domain}"),
            ("webarchive", f"https://web.archive.org/cdx/search/cdx?url=*.{self.domain}/*&output=txt"),
        ]

        if self.vt_key:
            s.append(("virustotal", f"https://www.virustotal.com/vtapi/v2/domain/report?apikey={self.vt_key}&domain={self.domain}"))
        if self.shodan_key:
            s.append(("shodan", f"https://api.shodan.io/dns/domain/{self.domain}?key={self.shodan_key}"))

        return s

    # _fetch: perform a single HTTP GET to a service endpoint.
    # It returns (name, text). If failure, return empty text.
    # Example: await _fetch(client, "crtsh", url) -> ("crtsh", "[{...}]")
    async def _fetch(self, client: httpx.AsyncClient, name: str, url: str) -> Tuple[str, str]:
        try:
            r = await client.get(url, timeout=self.timeout)
            r.raise_for_status()
            return name, r.text
        except Exception as e:
            if not self.silent:
                logger.debug("Recon fetch error %s: %s", name, e)
            return name, ""

    # _parse: parse the response text from a named service.
    # It extracts candidate subdomains and returns them as a list.
    # Example: _parse("crtsh", "[{...}]") -> ["sub.example.com"]
    def _parse(self, name: str, text: str) -> List[str]:
        # best-effort parsers similar to original
        out: List[str] = []
        if not text:
            return out
        try:
            if name == "alienvault":
                data = json.loads(text)
                out = [it["hostname"] for it in data.get("passive_dns", []) if it.get("hostname", "").endswith(self.domain)]
            elif name == "virustotal":
                data = json.loads(text)
                out = [s for s in data.get("subdomains", []) if s.endswith(self.domain)]
            elif name == "shodan":
                data = json.loads(text)
                out = [f"{s}.{self.domain}" for s in data.get("subdomains", [])]
            elif name == "certspotter":
                data = json.loads(text)
                for it in data:
                    for dn in it.get("dns_names", []):
                        if dn.endswith(self.domain):
                            out.append(dn)
            elif name == "crtsh":
                data = json.loads(text)
                out = [it.get("common_name") for it in data if it.get("common_name", "").endswith(self.domain)]
            elif name == "hackertarget":
                lines = [l for l in text.splitlines() if l.strip()]
                out = [l.split(",")[0].strip() for l in lines if l.split(",")[0].strip()]
            elif name == "rapiddns":
                soup = bs4.BeautifulSoup(text, "html.parser")
                out = [td.text.strip() for td in soup.find_all("td") if td.text.strip().endswith(self.domain)]
            elif name == "webarchive":
                pat = re.compile(r"https?://([^/]+)")
                hosts = [m.group(1) for m in (pat.search(l) for l in text.splitlines()) if m]
                out = [h for h in hosts if h.endswith(self.domain) and re.match(r"^[A-Za-z0-9\-\._]+$", h)]
        except Exception:
            # silent best-effort
            pass
        return out

    # start: run all services in parallel and collect subdomains.
    # Returns a sorted unique list of subdomains.
    # Example: subs = await Recon("example.com").start()
    async def start(self) -> List[str]:
        services = self.services()
        results: List[str] = []
        limits = asyncio.Semaphore(self.max_concurrency)
        async with httpx.AsyncClient(headers=self.headers, http2=True) as client:
            tasks = []
            for name, url in services:
                async def worker(n=name, u=url):
                    async with limits:
                        return await self._fetch(client, n, u)
                tasks.append(asyncio.create_task(worker()))
            for coro in asyncio.as_completed(tasks):
                name, text = await coro
                results += self._parse(name, text)
        unique = [s for s in OrderedDict.fromkeys(results) if "*" not in s and s]
        return sorted(unique)

# ---------------------------
# Async DNS + HTTP + Cert checks
# ---------------------------

# AsyncScanner class:
# - Resolve a domain to IP(s).
# - Check http and https responses and headers.
# - Fetch certificate details and check TLS versions.
# - It caches DNS results to avoid repeated lookups.
#
# Example:
#   s = AsyncScanner("sub.example.com")
#   info = await s.scan()
#   # info -> {"domain":"sub.example.com", "ip": [...], "http": [...], "https": [...], "cert": [...]}
class AsyncScanner:
    DNS_CACHE: Dict[str, Optional[List[str]]] = {}
    CERT_SEMAPHORE = asyncio.Semaphore(50)

    def __init__(self, domain: str, dns_server: Optional[str] = None, useragent: Optional[str] = None,
                 timeout: float = 2.0, concurrency: int = 200, ssl_verify: bool = False,
                 root_domain: Optional[str] = None, silent: bool = False):
        # Initialize basic scanner state.
        self.domain = domain
        self.dns_server = dns_server or "8.8.8.8"
        self.headers = {"User-Agent": useragent or random.choice(USER_AGENTS)}
        self.timeout = timeout
        self.concurrency = concurrency
        self.ssl_verify = ssl_verify
        self.client = None
        # store the original root domain to check certificate SAN against it
        # if not provided, fallback to the instance domain
        self.root_domain = root_domain or domain

    # _resolve_async:
    # - Resolve A records for a domain using the synchronous dns.resolver in a threadpool.
    # - Cache the results in DNS_CACHE.
    # Example: ips = await _resolve_async("sub.example.com") -> ["1.2.3.4"]
    async def _resolve_async(self, domain: str) -> Optional[List[str]]:
        if not hasattr(self, "DNS_CACHE"):
            self.DNS_CACHE = {}

        """Resolve A records asynchronously or via threadpool; with caching."""
        if domain in self.DNS_CACHE:
            return self.DNS_CACHE[domain]

        ips: Optional[List[str]] = None  # ensure variable is always defined

        loop = asyncio.get_running_loop()
        def sync_resolve():
            r = dns.resolver.Resolver()
            r.nameservers = [self.dns_server]
            r.timeout = self.timeout
            r.lifetime = self.timeout
            try:
                answers = r.resolve(domain, "A")
                return [str(a) for a in answers]
            except Exception:
                return None
        ips = await loop.run_in_executor(None, sync_resolve)

        # cache result (even None) to avoid repeated lookups
        self.DNS_CACHE[domain] = ips
        self.DNS_CACHE[f"{domain}_timestamp"] = asyncio.get_event_loop().time()
        return ips


    # _http_check:
    # - Perform an HTTP GET to the given URL using the AsyncClient stored in self.client.
    # - Return (status_code, redirect_location, server_header, content_length).
    # Example: await _http_check("http://sub.example.com") -> (200, None, "nginx", 1250)
    async def _http_check(self, url: str) -> Tuple[Optional[int], Optional[str], Optional[str], Optional[int]]:
        try:
            r = await self.client.get(url, timeout=self.timeout, follow_redirects=False)
            return r.status_code, r.headers.get("Location"), r.headers.get("Server"), len(r.content)
        except Exception:
            return None, None, None, None

    # _cert_fetch:
    # - Blocking part (run in threadpool) gets certificate, expiry, common name and checks SANs.
    # - It uses a semaphore self.CERT_SEMAPHORE to limit concurrent cert checks.
    # - Then it calls _check_tls_versions() to get a list of TLS versions supported by the host.
    # - The function returns (is_valid, expiry_iso, common_name, tls_versions_list).
    #
    # Example:
    #   cert_info = await _cert_fetch()
    #   # cert_info -> (True, "2026-09-15", "example.com", ["TLS 1.3", "TLS 1.2"])
    async def _cert_fetch(self) -> Tuple[Optional[bool], Optional[str], Optional[str], Optional[List[str]]]:
        """
        Fetch and analyze the SSL certificate for self.domain, then check supported TLS versions.
        """
        loop = asyncio.get_running_loop()

        # sync part: runs in threadpool
        def sync_cert():
            try:
                pem = ssl.get_server_certificate((self.domain, 443))
                x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, pem)
                not_after = x509.get_notAfter().decode("utf-8")
                expiry = datetime.strptime(not_after, "%Y%m%d%H%M%S%z").date().isoformat()
                is_valid = expiry >= datetime.now().date().isoformat()
                cn = x509.get_subject().commonName
                # Check SANs: ensure the original root_domain is present
                root = self.root_domain
                for i in range(x509.get_extension_count()):
                    ext = x509.get_extension(i)
                    if b"subjectAltName" in ext.get_short_name():
                        san = str(ext)
                        if root not in san and f"*.{root}" not in san:
                            is_valid = False
                return is_valid, expiry, cn
            except Exception:
                return None, None, None

        # run sync_cert() in a threadpool
        async with self.CERT_SEMAPHORE:
            is_valid, expiry, cn = await loop.run_in_executor(None, sync_cert)

        # run TLS check asynchronously
        tls_versions = await self._check_tls_versions()
        weak_versions = [v for v in tls_versions if v.startswith("SSLv") or v in ("TLS 1.0", "TLS 1.1")]
        if weak_versions:
            is_valid = False

        return is_valid, expiry, cn, tls_versions


    # _check_tls_versions:
    # - Test which TLS protocol versions the host supports.
    # - Each test uses a specific SSL context or a generic client context for TLS 1.3.
    # - This function runs the blocking checks in a threadpool and returns a list of version names.
    #
    # Example:
    #   versions = await _check_tls_versions()
    #   # versions -> ["TLS 1.3", "TLS 1.2"]
    async def _check_tls_versions(self) -> List[str]:
        """
        Detect which TLS protocol versions are supported by the target host.
        Runs the blocking socket tests in a threadpool.
        Returns a list like ["TLS 1.3", "TLS 1.2"].
        """
        loop = asyncio.get_running_loop()

        def sync_tls_check() -> List[str]:
            """Return supported TLS versions for this host, safely across Python versions."""
            # Build dictionary only with versions actually supported by current ssl module
            tls_versions = {}
            if hasattr(ssl, "PROTOCOL_TLSv1"):
                tls_versions["TLS 1.0"] = ssl.PROTOCOL_TLSv1
            if hasattr(ssl, "PROTOCOL_TLSv1_1"):
                tls_versions["TLS 1.1"] = ssl.PROTOCOL_TLSv1_1
            if hasattr(ssl, "PROTOCOL_TLSv1_2"):
                tls_versions["TLS 1.2"] = ssl.PROTOCOL_TLSv1_2
            # TLS 1.3 constant may not exist; try generic client context instead
            if hasattr(ssl, "PROTOCOL_TLSv1_3"):
                tls_versions["TLS 1.3"] = ssl.PROTOCOL_TLSv1_3
            else:
                # fallback: test with PROTOCOL_TLS_CLIENT which will negotiate TLS 1.3 if supported
                tls_versions["TLS 1.3"] = ssl.PROTOCOL_TLS_CLIENT # via generic context

            supported = []
            for name, proto in tls_versions.items():
                try:
                    ctx = ssl.SSLContext(proto)
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                    with socket.create_connection((self.domain, 443), timeout=self.timeout) as sock:
                        with ctx.wrap_socket(sock, server_hostname=self.domain):
                            supported.append(name)
                except ssl.SSLError:
                    continue
                except Exception:
                    continue
            return supported

        return await loop.run_in_executor(None, sync_tls_check)

    # scan:
    # - Main function to check the domain.
    # - It resolves DNS, checks http and https, handles http redirects, and runs certificate check if https is present.
    # - It returns a dict with domain, ip, http, https and cert info.
    #
    # Example:
    #   result = await AsyncScanner("sub.example.com").scan()
    #   # result keys: domain, ip, http, https, cert
    async def scan(self) -> Optional[Dict[str, Any]]:
        # create client per-scan to respect headers / http2
        async with httpx.AsyncClient(headers=self.headers, http2=True, verify=self.ssl_verify) as client:
            self.client = client
            ips = await self._resolve_async(self.domain)
            if not ips:
                return None
            http = await self._http_check(f"http://{self.domain}")
            https = await self._http_check(f"https://{self.domain}")
            # handle redirect to other domain for https
            if http[0] and http[1] and not https[0]:
                loc = http[1]
                if not loc.startswith(("http://", "https://")):
                    loc = "http://" + loc
                redirected = loc.split("://", 1)[1].split("/")[0]
                https = await self._http_check(f"https://{redirected}")
            cert = (None, None, None, None)
            if https[0]:
                #cert = await self._cert_fetch(self.domain)
                cert = await self._cert_fetch()
            return {"domain": self.domain, "ip": ips, "http": list(http), "https": list(https), "cert": list(cert)}

# ---------------------------
# Orchestration: top-level async runner
# ---------------------------

# _run_async:
# - Expand domains when recon or bruteforce is requested.
# - If single domain, scan directly.
# - If many domains, schedule many AsyncScanner workers with concurrency limits.
# - Uses a CERT_SEMAPHORE to limit concurrent certificate checks (heavy operations).
#
# Example:
#   results = asyncio.run(_run_async(["example.com"], ...))
async def _run_async(domains: List[str], dns: Optional[str], useragent: Optional[str],
                     timeout: Optional[float], threads: Optional[int],
                     recon: bool, bruteforce: bool, wordlist: Optional[str],
                     silent: bool) -> Union[List[dict], dict, None]:
    # expansion
    if recon or bruteforce:
        expanded: List[str] = []
        base = domains[0]
        if recon:
            if not silent:
                print("Reconnaissance...")
            r = Recon(base, timeout=(timeout or 2.0), silent=silent, max_concurrency=40)
            expanded += await r.start()
        if bruteforce:
            if not silent:
                print("Bruteforcing...")
            b = Bruteforce(base, wordlist)
            expanded += b.start()
        domains = list(OrderedDict.fromkeys(domains + expanded))
    # single domain shortcut
    if len(domains) == 1:
        scanner = AsyncScanner(domains[0], dns_server=dns, useragent=useragent, timeout=(timeout or 1.5), root_domain=domains[0])
        return await scanner.scan()
    # many domains concurrently with bounded concurrency
    max_workers = threads or min(300, max(20, len(domains)))
    sem = asyncio.Semaphore(max_workers)
    CERT_SEMAPHORE = asyncio.Semaphore(50)

    async def worker(d):
        async with sem:
            s = AsyncScanner(d, dns_server=dns, useragent=useragent, timeout=(timeout or 1.5), root_domain=domains[0], silent=silent)
            # give AsyncScanner access to semaphores (optionally)
            s.CERT_SEMAPHORE = CERT_SEMAPHORE
            return await s.scan()

    tasks = [asyncio.create_task(worker(d)) for d in domains]

    results = []
    if not silent:
        total = len(tasks)
        done = 0
        for fut in asyncio.as_completed(tasks):
            res = await fut
            done += 1
            if res:
                results.append(res)
            print(f"\rScanned {done}/{total} domains...", end="", flush=True)
        print()
    else:
        for fut in asyncio.as_completed(tasks):
            res = await fut
            if res:
                results.append(res)

    return results

# KNOCKPY:
# - Synchronous wrapper for _run_async so the CLI can call it.
# - Accepts domain string or iterable of domains.
# - Example: res = KNOCKPY("example.com")
def KNOCKPY(domain: Union[str, Iterable[str]],
            dns: Optional[str]=None, useragent: Optional[str]=None, timeout: Optional[float]=None,
            threads: Optional[int]=None, recon: bool=False, bruteforce: bool=False,
            wordlist: Optional[str]=None, silent: bool=False) -> Union[List[dict], dict, None]:
    """Synchronous entrypoint that wraps the async runner."""
    if isinstance(domain, str):
        domains = [domain]
    else:
        domains = list(domain)
    return asyncio.run(_run_async(domains, dns, useragent, timeout, threads, recon, bruteforce, wordlist, silent))

# ---------------------------
# Output & utilities
# ---------------------------

# output:
# - Nice console formatter for results.
# - If json_output True, dump JSON to stdout.
# - Example: output(result)
def output(results: Union[dict, List[dict], None], json_output: bool=False, elapsed: Optional[timedelta]=None) -> None:
    if not results:
        return
    if json_output:
        json.dump(results, sys.stdout, indent=2)
        sys.exit(0)
    if isinstance(results, dict):
        results = [results]
    RED, MAG, YEL, CYA, END = "\033[1;31m", "\033[1;35m", "\033[1;33m", "\033[1;36m", "\033[0m"
    print()
    for item in results:
        ok_http  = item["http"][0] != None
        ok_https = item["https"][0] != None
        ok_cert  = bool(item["cert"][0])
        if all(v is None for v in item["http"]) and all(v is None for v in item["https"]):
            print(f"{MAG}{item['domain']}{END}", item["ip"])
        elif ok_http and not ok_cert:
            print(f"{RED}{item['domain']}{END}", item["ip"])
        else:
            print(f"{CYA}{item['domain']}{END}", item["ip"])
        http_label  = "http  "# if ok_http else f"{YEL}http {END}"
        https_label = f"{YEL}https {END}" if not ok_https and ok_http else "https "
        cert_label  = f"{YEL}cert  {END}" if not ok_cert and ok_https else "cert  "
        print(http_label, item["http"])
        print(https_label, item["https"])
        print(cert_label, item["cert"])
        #print()
        print("-" * 60)
    print(len(results), "domains in", fmt_td(elapsed))

# save:
# - Save scan results as JSON file with timestamp.
# - Example: save("example.com", results, "reports")
def save(domain: str, results: List[dict], folder: Optional[str]) -> None:
    dt = datetime.now().strftime("%Y_%m_%d_%H_%M_%S")
    if folder:
        os.makedirs(folder, exist_ok=True)
        path = os.path.join(folder, f"{domain}_{dt}.json")
    else:
        path = f"{domain}_{dt}.json"
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(results, fh, indent=2)

# show_report:
# - Load a saved JSON report and print it.
# - If the file is missing, print helpful hints instead of crashing.
# - Example: show_report("reports/example_2025_01_01_12_00_00.json", False)
def show_report(report_name: str, json_output: bool) -> None:
    """
    Load a saved report and display it.
    If the file does not exist, print a helpful message instead of raising.
    """
    if not report_name:
        print("No report file provided.")
        return

    if not os.path.exists(report_name):
        print(f"Report file not found: {report_name}")
        # suggest possible saved files
        saved = [f for f in os.listdir('.') if f.endswith('.json')]
        if saved:
            print("Saved JSON files in current dir:")
            for s in saved:
                print("  -", s)
        else:
            print("No saved JSON reports found in current directory.")
        return

    try:
        with open(report_name, "r", encoding="utf-8") as f:
            report = json.load(f)
    except Exception as e:
        print(f"Error reading report '{report_name}': {e}")
        return

    output(report, json_output)

def print_scan_settings(timeout, threads, dns, useragent, recon, brute, save):
    print("\nScan settings:")
    print(f"- Timeout:    {timeout}")
    print(f"- Threads:    {threads or 'auto'}")
    print(f"- DNS:        {dns}")
    print(f"- User-agent: {useragent}")
    print(f"- Recon:      {recon}")
    print(f"- Bruteforce: {brute}")
    print(f"- Save:       {save}")


# ---------------------------
# CLI
# ---------------------------

# main:
# - Parse arguments and run the tool.
# - Accepts domain or file, recon, bruteforce, wildcard, save, report, json, etc.
# - Example: python knockpy.py -d example.com --recon --bruteforce --threads 100
def main():
    p = argparse.ArgumentParser(prog="KNOCKPY", description=f"knockpy v.{__version__} - Async Subdomain Scan\nhttps://github.com/guelfoweb/knock")
    p.add_argument("-d","--domain", help="Domain to analyze.")
    p.add_argument("-f","--file", help="File with domains, one per line.")
    p.add_argument("--dns", help="Custom DNS server.", dest="dns", required=False)
    p.add_argument("--useragent", help="Custom User-Agent.", dest="useragent", required=False)
    p.add_argument("--timeout", help="Timeout (seconds).", dest="timeout", type=float, required=False)
    p.add_argument("--threads", help="Number of concurrent workers.", dest="threads", type=int, required=False)
    p.add_argument("--recon", help="Enable reconnaissance.", action="store_true")
    p.add_argument("--bruteforce", "--brute", help="Enable bruteforce.", action="store_true")
    p.add_argument("--wordlist", help="Path to wordlist file.", dest="wordlist", required=False)
    p.add_argument("--wildcard", help="Test wildcard and exit.", action="store_true")
    p.add_argument("--json", help="Output JSON.", action="store_true")
    p.add_argument("--save", help="Directory to save results.", dest="folder", required=False)
    p.add_argument("--report", help="Show saved report.", dest="report", required=False)
    p.add_argument("--silent", help="Silent mode (fewer prints).", action="store_true")
    p.add_argument("--logfile", help="Write logs to file.", dest="logfile", required=False)
    p.add_argument("--show-settings", help="Print effective scan settings and continue.", action="store_true")
    args = p.parse_args()

    if args.logfile:
        fh = logging.FileHandler(args.logfile)
        fh.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
        logger.addHandler(fh)
        logger.setLevel(logging.DEBUG)

    # stdin handling as original
    if not args.domain and not args.file and not sys.stdin.isatty():
        lines = [l.strip() for l in sys.stdin.read().splitlines() if l.strip()]
        if len(lines) == 1:
            if os.path.isfile(lines[0]):
                args.file = lines[0]
            else:
                args.domain = lines[0]
        elif len(lines) > 1:
            args.domain = lines

    if args.report:
        show_report(args.report, args.json)
        return

    if not args.domain and not args.file:
        p.print_help(sys.stderr)
        return

    if args.domain:
        domain_input = args.domain

        # determine actual values
        timeout = args.timeout if args.timeout is not None else 2.0
        threads = args.threads if args.threads is not None else None
        dns = args.dns or "8.8.8.8"
        useragent = args.useragent or "random"

        if not args.silent and args.show_settings:
            print_scan_settings(timeout, threads, dns, useragent, args.recon, args.bruteforce, bool(args.folder))

        if args.wildcard and isinstance(domain_input, str):
            w = Bruteforce(domain_input).wildcard()
            start_time = datetime.now()
            res = KNOCKPY(w, dns=dns, useragent=useragent, timeout=timeout, threads=threads, recon=False, bruteforce=False, wordlist=None, silent=args.silent)
            elapsed = datetime.now() - start_time
            output(res, args.json, elapsed)
            return

        # KNOCKPY handles recon/bruteforce expansions
        start_time = datetime.now()
        res = KNOCKPY(domain_input, dns=dns, useragent=useragent, timeout=timeout, threads=threads, recon=args.recon, bruteforce=args.bruteforce, wordlist=args.wordlist, silent=args.silent)
        elapsed = datetime.now() - start_time

        if (args.recon or args.bruteforce) and isinstance(res, list):
            save(args.domain if isinstance(args.domain, str) else args.domain[0], res, args.folder)

        output(res, args.json, elapsed)
        return

    if args.file:
        # reuse values
        timeout = args.timeout if args.timeout is not None else 2.0
        threads = args.threads if args.threads is not None else None
        dns = args.dns or "8.8.8.8"
        useragent = args.useragent or "random"

        if not args.silent and args.show_settings:
            print_scan_settings(timeout, threads, dns, useragent, False, False, bool(args.folder))

        with open(args.file, "r", encoding="utf-8") as fh:
            domains = [l.strip() for l in fh if l.strip()]
        start_time = datetime.now()
        res = KNOCKPY(domains, dns=args.dns, useragent=args.useragent, timeout=args.timeout, threads=args.threads, recon=False, bruteforce=False, wordlist=None, silent=args.silent)
        elapsed = datetime.now() - start_time
        output(res, args.json, elapsed)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nInterrupted", file=sys.stderr)
        try:
            sys.exit(0)
        except SystemExit:
            os._exit(0)
