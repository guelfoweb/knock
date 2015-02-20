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

def start(target):
	found_alias = []
	found_host = []
	try:
		ipv4 = socket.gethostbyname(target) # Ip Address format
		if ipv4:
			soc = socket.gethostbyname_ex(target)
			# print soc, target # enable for debug
			for alias in soc[1]:
				try:
					# alias -> ip
					ipaddr = socket.gethostbyname(alias)
					found_alias.append([alias, ipaddr])
				except:
					pass

			hostname = soc[0]
			for ipaddr in soc[2]:
				found_host.append([hostname, ipaddr])

		soc.close()
	except: pass
	
	if found_alias or found_host:
		return found_alias, found_host
	else:
		return False

def hostbyip(ip):
	try:
		return socket.gethostbyaddr(ip)[0]
	except:
		return False
