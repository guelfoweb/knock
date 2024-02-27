from knock import KNOCKPY

domain = 'github.com'

results = KNOCKPY(domain, dns=None, useragent=None, timeout=None, threads=None, recon=True, bruteforce=True, wordlist=None)

print (results)