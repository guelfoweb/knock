#!/usr/bin/env python
# -*- coding: utf-8 -*-

# ----------------------------------------------------------------------
# This file is part of Knock subdomain scan (aka knockpy)
#
# Knock is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Knock is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Knock. If not, see <http://www.gnu.org/licenses/>.
# ----------------------------------------------------------------------

import getheader
import headers
import stats
import target
import utilipy
import wildcard
import wordlist
import subscan
import zonetransfer
import font

def start_scan(wildcard_detected, code):
	# Subdomains target
	for target in targetlist:
		if wildcard_detected:
			result = core.bypass_wildcard(target, code)
		else:
			result = core.get_target(target, False, False)
		if result:
			return result

def get_header(url, path, method):
	return getheader.req(url, path, method)

def subscan_start(target):
	return subscan.start(target)

def get_info_wordlist(path_to_worlist=False):
	return wordlist.check_status(path_to_worlist)

def prepare_targetlist(domain, wordlist):
	targets = []
	for sub in wordlist:
		targets.append(sub+'.'+domain)
	return targets

def logic_wildcard_detect(status, reason, header):
	return wildcard.logic(status, reason, header)

def get_target(_target, verbose, test):
	return target.get(_target, verbose, test)
		
def stats_general_summary(targetlist):
	return stats.start(found, targetlist)

def bypass_wildcard(target, code):
	if wildcard.bypass(target, code):
		return get_target(target, True, False)

def test_wildcard(target):
	return wildcard.test(target)

host_not_found = False
wildcard_detected = False

# Resolve domain
def header_target(domain):
	print headers.target(domain)

def show_resolved(domain, resolve):
	# return alias and host
	getinfo_host = subscan.start(domain)

	test_domain = True
	
	# domain not found, exit
	if not getinfo_host and test_domain:
		print font.color('red')+'\n: unknown '+domain+font.color('end')
		
		# if option [-r, --resolve] is true -> is testing
		if resolve: exit()
		
		# prepare query [c] -> continue, [enter] -> exit
		query = 'press '+font.color('bold')+'[c]'\
		+font.color('end')+' to continue to scan or '\
		+font.color('bold')+'[enter]'+font.color('end')\
		+' to exit: '
		
		# prompt
		res = raw_input(query)
		if res != 'c': exit()

		# set global and return
		#global test_domain
		#global host_not_found
		#global wildcard_detected
		test_domain = False
		host_not_found = True
		wildcard_detected = False

		return
		
	# get alias and host list
	(alias, host) = getinfo_host[0], getinfo_host[1]

	output = ''

	# if alias exist
	if alias: 
		for name in alias:
			(ipaddr, aliasn) = str(name[1]), str(name[0])
			output += font.color('yellow')+ipaddr.ljust(18)+aliasn+'\n'+font.color('end')

	# host always exists
	len_host = len(host)
	for i in xrange(0, len_host):
		# get hostname by ip
		(ipaddr, hostname) = host[i][1], host[i][0]
		if ipaddr == hostname:
			hostname = subscan.hostbyip(domain)

		output += ipaddr.ljust(18)+hostname+'\n'

	print output

# Code and headers
def get_banner(domain):
	if host_not_found: return
	# return [headers]
	# status, reason, headers
	# len = 3
	getinfo_header = getheader.req(domain,'/','HEAD')
	# set to global
	global code, reason, header
	if not getinfo_header: 
		(code, header) = False, False
		return
	(code, reason, header) = str(getinfo_header[0]), str(getinfo_header[1]), getinfo_header[2]
	
def header_response_code():
	if host_not_found: return
	print headers.response_code()

def header_response_head():
	if host_not_found: return
	print headers.response_head()

def show_banner(typo):
	if host_not_found: return
	# print code and reason
	if typo == 'code' and code:	print code.ljust(18)+reason+'\n'
	
	# print headers field
	if typo == 'head' and header:
		for head in header:
			# output first chars: 17 fields | 61 values
			print str(head[0])[0:17].ljust(18)+str(head[1])[0:61]

# Wildcard, wordlist, targetlist
def show_wildcard(domain):
	if host_not_found: return
	# test wildcard
	global wildcard_detected
	wildcard_detected = False
	if wildcard.test(domain):
		wildcard_detected = True
		print font.color('red')+'\n: wildcard detected'+font.color('end')

def get_wordlist(domain, path_to_worlist=False):
	# import wordlist
	getinfo_wordlist = get_info_wordlist(path_to_worlist)
	global wordlist
	(location, wordlist) = getinfo_wordlist[0], getinfo_wordlist[1]
	print headers.status_wordlist(location, wordlist)
	
def get_targetlist(domain):
	# prepare subdomain.domain.com
	global targetlist
	targetlist = prepare_targetlist(domain, wordlist)

# Start
def header_start_scan(domain):
	print headers.start_scan(domain)

def subdomain_scan():
	for target in targetlist:
		if wildcard_detected:
			result = bypass_wildcard(target, code)
		else:
			result = get_target(target, False, False)

		if result:
			print result

# Statistics
def header_stats_summary():
	return headers.stats_summary()

def report():
	print target.get_report(targetlist)

# Save result in csv
def save_in_csv(domain):
	print target.save_csv(domain)

# Zone transfer
def getzone(domain):
	detected = zonetransfer.check(domain)
	if not detected: exit('zone transfer not found')
	print headers.start_scan_zt(domain)
	for item in detected:
		(ip, subdomain) = str(item[0]), str(item[1])
		print ip.ljust(18)+subdomain

