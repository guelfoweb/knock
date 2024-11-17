from knock import KNOCKPY

domain = 'github.com'
dns = "8.8.8.8"
useragent = "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:33.0) Gecko/20120101 Firefox/33.0"
timeout = 2
threads = 10

results = KNOCKPY(
	domain,
	#silent=True,
	dns=dns, 
	useragent=useragent, 
	timeout=timeout, 
	threads=threads, 
	recon=True, 
	bruteforce=True, 
	wordlist=None)

print (results)