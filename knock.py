#!/usr/bin/env python

# Knock Subdomain Scan
#
# Knock is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Knock is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Knock. If not, see <http://www.gnu.org/licenses/>.

import sys

sys.path.insert(0, 'modules')

try:
		import knockcore
except ImportError:
		print '[!] knockcore not found.'
		sys.exit(0)

# INFORMATION
NAME		= "Knock Subdomain Scan"
VERSION		= "2.0"
AUTHOR		= "Author: Gianni 'guelfoweb' Amato"
GITHUB		= "Github: https://github.com/guelfoweb/knock"
INFO		= NAME+" v."+VERSION+" - Open Source Project\n"+AUTHOR+"\n"+GITHUB

# color const
COLOR_ALIAS = '\033[93m'
COLOR_RED   = '\033[91m'
COLOR_BOLD  = '\033[1m'
COLOR_END   = '\033[0m'

def uniq_by_array(array):
	uniq_ip   = []
	uniq_name = []
	array_row = len(array)
	for i in range(0,array_row):
		a  = array[i][0]
		b  = array[i][1]
		if a not in uniq_ip:
			uniq_ip.append(a)
		if b not in uniq_name:
			uniq_name.append(b)

	print COLOR_BOLD + "Ip Addr Summary" + COLOR_END
	print "-"*15
	for i in range(0,len(uniq_ip)):
		print uniq_ip[i]

	host_found = len(uniq_ip)
	name_found = len(uniq_name)
	print "\nFound "+str(name_found)+" subdomain(s) in "+str(host_found)+" host(s)."
	

def resolvedomain(subdomain):
	result    = knockcore.domaininfo(subdomain)

#		 [ 4 x 3 ]								[ 3 x 3 ]
#		 [['hostname'],                0
#		  ['alias', 'alias', 'ip'],    1 0
#		  ['alias', 'alias', 'ip'],    2 1
#		  ['alias', 'alias', 'ip']]    3 2
#		      0        1      2

#		 [ 3 x 3 ]								[ 2 x 3 ]
#		 [['login.lga1.b.yahoo.com'], 														  0
#		  ['login.yahoo.com',               'l2.login.vip.bf1.yahoo.com', '98.139.237.162'],  1 0
#		  ['login-global.lgg1.b.yahoo.com', 'l2.login.vip.bf1.yahoo.com', '98.139.237.162']]  2 1
#		                 0                                 1                       2

	# subdomain is alias
	if result and len(result) == 2 and len(result[1]) == 2:
		hostname = result[0][0]
		alias    = result[1][0]
		ip       = result[1][1]
		print COLOR_ALIAS + ip+"\t"+alias + COLOR_END
		print ip+"\t"+hostname
		found.append([ip, alias])
		found.append([ip, hostname])
	# subdomain is alias
	elif result and len(result) == 2 and len(result[1]) == 3:
		hostname = result[0][0]
		alias    = result[1][0]
		name     = result[1][1]
		ip       = result[1][2]
		print COLOR_ALIAS + ip+"\t"+alias + COLOR_END
		print ip+"\t"+hostname
		found.append([ip, alias])
		found.append([ip, hostname])
	# subdomain is alias
	elif result and not len(result) == 2 and not False:
		uniq = []
		for i in range(1,len(result)):
			ip_alias = result[i][2]+"\t"+result[i][0]
			ip_name  = result[i][2]+"\t"+result[i][1]
			
			if ip_alias not in uniq:
				uniq.append(ip_alias)
				print COLOR_ALIAS + ip_alias + COLOR_END
				found.append([result[i][2], result[i][0]])
			if ip_name not in uniq:
				uniq.append(ip_name)
				print ip_name
				found.append([result[i][2], result[i][1]])
		for i in range(1,len(result)):
			ip_hostname  = result[i][2]+"\t"+result[0][0]
			if ip_hostname not in uniq:
				uniq.append(ip_hostname)
				print ip_hostname
				found.append([result[i][2], result[0][0]])
	# subdomain is hostname
	elif result:
		hostname = result[0][0]
		ip       = result[1][0]
		print ip+"\t"+hostname
		found.append([ip, hostname])

def loadwordlist(wordlist):
	wlist = knockcore.loadfile(wordlist)
	if wlist == False:
		print COLOR_RED + "\nFile not found ["+wordlist+"]" + COLOR_END
		print "Download a wordlist file from here:"
		print "https://raw.github.com/guelfoweb/knock/master/wordlist.txt"
		sys.exit(0)
	return wlist

def subscan(url, wordlist):
	wlist = loadwordlist(wordlist)

	print COLOR_BOLD + "Getting subdomain for", url + COLOR_END
	print "\nIp Address\tDomain Name"
	print "----------\t-----------"

	for sub in wlist:
		subdomain = sub+"."+url
		resolvedomain(subdomain)

	print
	uniq_by_array(found)

def bypasswildcard(url, wordlist):
	wlist = loadwordlist(wordlist)

	print COLOR_BOLD + "\nGetting subdomain for", url + COLOR_END
	print "\nIp Address\tDomain Name"
	print "----------\t-----------"

	for sub in wlist:
		subdomain = sub+"."+url
		header = knockcore.getheader(subdomain, "/", "GET")
		# bypass status code -> header[0] = 301
		if header and not header[0] == 301:
			resolvedomain(subdomain)

	print
	uniq_by_array(found)

def checkzone(domain):
	print  COLOR_BOLD + "Getting NS records for", domain + COLOR_END
	print "\nIp Address\tServer Name"
	print "----------\t-----------"
	zt_found = knockcore.zonetransfer(url)
	if (zt_found):
		print COLOR_BOLD + "Getting Zone Transfer\n" + COLOR_END
		print "Ip Address\tDomain Name"
		print "----------\t-----------"
		for sub in zt_found:
			resolvedomain(sub)
		print
	else:
		return False

def getheaders(url, path, method):
	# Status -> header[0] 
	# Reason -> header[1]
	# Header -> header[2]
	header = knockcore.getheader(url, path, method)
	status = str(header[0])
	reason = str(header[1])
	print COLOR_BOLD + "Staus\tReason" +  COLOR_END
	print "-----\t------"
	print status + "\t" + reason
	print
	print COLOR_BOLD + "Response Headers" +  COLOR_END
	print "-"*16
	for i in range(1,len(header[2])):
		print str(header[2][i][0]) + ": " + str(header[2][i][1])
	return status, reason

def CheckForWildcard(url):
	# test wildcard and return True or False
	wildcard  = knockcore.testwildcard(url)
	
	if wildcard == False:
		return False
	else:
		print COLOR_RED+COLOR_BOLD+"Wildcard enabled\n"+COLOR_END

def check_status(url, path, method):
	try:
		header   = knockcore.getheader(url, path, method)
		status   = str(header[0])
		reason   = str(header[1])
		response = header[2]
		return status, reason, response
	except:
		sys.exit(0)

def purgeurl(url):
	url = url.replace("http://","")
	url = url.replace("/","")
	return url

def help():
	print COLOR_BOLD+INFO+COLOR_END
	print
	print COLOR_BOLD+"Usage:"+COLOR_END+" knock.py domain.com"
	print COLOR_BOLD+"Usage:"+COLOR_END+" knock.py domain.com "+COLOR_BOLD+"--worlist "+COLOR_END+"wordlist.txt"
	print "\n\t-h, --help\tThis help"
	print "\t-v, --version\tShow version"
	print "\t    --wordlist\tUse personal wordlist"
	print COLOR_BOLD+"\nOptions for single domain"+COLOR_END
	print "-"*25
	print "\t-i, --info\tShort information"
	print "\t-r, --resolve\tResolve domain name"
	print "\t-w, --wildcard\tCheck if wildcard is enabled"
	print "\t-z, --zone\tCheck if Zone Transfer is enabled"
#	print "\t    --get\tRequest HTTP for GET method"
#	print "\t    --post\tRequest HTTP for POST method"
#	print "\t    --head\tRequest HTTP for HEAD method"
#	print "\t    --trace\tRequest HTTP for TRACE method"
#	print "\t    --options\tRequest HTTP for OPTIONS method"
	print "\n"+" "*9+COLOR_BOLD+"Usage:"+COLOR_END+" knock.py"+COLOR_BOLD+" [-opt, --option]"+COLOR_END+" domain.com"
	print "\nNote: The ALIAS name is marked in yellow."
	sys.exit(0)

#___________________Main_____________________

global found
found = []
global wlist

if len(sys.argv) == 1 or len(sys.argv) > 4:
	help()

if len(sys.argv) == 2:
	url = sys.argv[1]
	url = purgeurl(url)
	if url == "-h" or url == "--help":
		help()
	if url == "-v" or url == "--version":
		print VERSION
		sys.exit(0)
	if CheckForWildcard(url) == False:
		checkzone(url)
		subscan(url, "wordlist.txt")
	else:
		checkzone(url)
		getheaders(url, "/", "GET")
		bypasswildcard(url, "wordlist.txt")
	sys.exit(0)

if len(sys.argv) == 3:
	opt = sys.argv[1]
	url = sys.argv[2]
	url = purgeurl(url)
	if opt == "-i" or opt == "--info":
		print COLOR_BOLD + "Resolving domain", url + "\n" + COLOR_END
		resolvedomain(url)
		print
		if checkzone(url) == False:
			print "Zone Transfer not enabled\n"
		CheckForWildcard(url)
		getheaders(url, "/", "GET")

	if opt == "-r" or opt == "--resolve":
		print COLOR_BOLD + "Resolving domain", url + "\n" + COLOR_END
		resolvedomain(url)
	if opt == "-w" or opt == "--wildcard":
		CheckForWildcard(url)
	if opt == "-z" or opt == "--zone":
		if checkzone(url) == False:
			print "Zone Transfer not enabled"

	# ------- hidden for debug -------
	if opt == "--trace":
		getheaders(url, "/", "TRACE")
	if opt == "--get":
		getheaders(url, "/", "GET")
	if opt == "--post":
		getheaders(url, "/", "POST")
	if opt == "--head":
		getheaders(url, "/", "HEAD")
	if opt == "--options":
		getheaders(url, "/", "OPTIONS")
	# --------------------------------

	sys.exit(0)

if len(sys.argv) == 4:
	url   = sys.argv[1]
	url   = purgeurl(url)
	opt   = sys.argv[2]
	wlist = sys.argv[3]
	if opt == "--wordlist":
		if CheckForWildcard(url) == False:
			checkzone(url)
			subscan(url, wlist)
		else:
			checkzone(url)
			getheaders(url, "/", "GET")
			bypasswildcard(url, wlist)
	sys.exit(0)

