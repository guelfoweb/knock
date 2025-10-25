#!/usr/bin/env python3
"""
Proof of Concept for KnockPy
Tests the KNOCKPY function against a target domain
"""
import sys
import os

# Root to sys.path (only for test)
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from knock import KNOCKPY
from datetime import datetime
import json

# ---- Configurable parameters ----
domain = "github.com"        # target domain
dns = "8.8.8.8"              # DNS resolver
useragent = "Mozilla/5.0 (Test Agent)"
timeout = 2.0                # per-request timeout
threads = 10                 # number of concurrent workers
recon = True                 # enable passive subdomain recon
bruteforce = False           # enable bruteforce (requires wordlist)
wordlist = None              # use default if None
silent = True                # silent mode

# ---- Run scan ----
print(f"[*] Starting KnockPy test on: {domain}")
start_time = datetime.now()

results = KNOCKPY(
    domain,
    dns=dns,
    useragent=useragent,
    timeout=timeout,
    threads=threads,
    recon=recon,
    bruteforce=bruteforce,
    wordlist=wordlist,
    silent=silent,
)

elapsed = datetime.now() - start_time
print(f"\n[*] Scan completed in {elapsed}")

# ---- Basic assertions ----
if not results:
    print("[!] No results returned.")
    sys.exit(1)

if isinstance(results, dict):
    results = [results]

print(f"[*] Found {len(results)} domains:\n")

# ---- Pretty output ----
for r in results:
    print("-" * 60)
    print(f"Domain:     {r['domain']}")
    print(f"IP(s):      {', '.join(r['ip']) if r.get('ip') else 'N/A'}")
    print(f"HTTP:       {r['http'][0]} ({r['http'][1] or 'no redirect'})")
    print(f"HTTPS:      {r['https'][0]} ({r['https'][1] or 'no redirect'})")
    print(f"Cert OK:    {r['cert'][0]}")
    print(f"Expiry:     {r['cert'][1]}")
    print(f"CommonName: {r['cert'][2]}")
    print(f"TLS:        {', '.join(r['cert'][3] or [])}")
print("-" * 60)
