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

import socket

# set the default timeout on sockets to 5 seconds
if hasattr(socket, 'setdefaulttimeout'):
	socket.setdefaulttimeout(5) # <- here

try:
	import dns.resolver, dns.query, dns.zone
except:
	exit('ImportError: No module named dnspython\ninstall python-dnspython')

def zonetransfer(domain): # Zone Transfer
	ns = []
	try:
		answers = dns.resolver.query(domain,'NS')
	except: exit('zone transfer not found')
	
	for rdata in answers:
		rdata = str(rdata).rstrip('.')
		ns.append(hostbyname(rdata))

	for n in ns:
		zt = []
		try:
			zone = dns.zone.from_xfr(dns.query.xfr(n, domain))
		except: exit('zone transfer not found')
		if zone:
			for name, node in zone.nodes.items():
				rdataset = node.rdatasets
				for record in rdataset:
					name = str(name)
					if name != '@' and name != '*':
						zt.append(name+'.'+domain)
			return zt

def hostbyname(domain):
	try:
		# translate a host name to IPv4 address format
		return socket.gethostbyname(domain)
	except:
		return False

def check(domain):
	found_list = []
	if hostbyname(domain):
		detected = zonetransfer(domain)
		for subdomain in detected:
			ip = hostbyname(subdomain)
			if ip: found_list.append([ip, subdomain])
		return found_list
	else:
		return False
