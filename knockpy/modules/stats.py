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
import font

def cogito(found, targetlist):
	# print found # enable for debug
	ipaddr = []
	subdomain = []
	subdomain_in_wlist = []
	subdomain_for_ip = []

	len_found = len(found)

	# ip address discovered
	for i in xrange(0, len_found):
		ipaddr.append(found[i][1])
	uniq_ipaddr = set(ipaddr)

	# subdomain discovered
	for i in xrange(0, len_found):
		subdomain.append(found[i][2])
	uniq_subdomain = set(subdomain)
	
	# subdomain in wordlist
	for subdomain in uniq_subdomain:
		if subdomain in targetlist:
			subdomain_in_wlist.append(subdomain)
	uniq_wlist = set(subdomain_in_wlist)

	report = '\nFound '+font.color('bold')+str(len(uniq_subdomain))\
	+font.color('end')+' subdomain(s) in '+font.color('bold')+str(len(uniq_ipaddr))+font.color('end')+' host(s).\n'\
	+font.color('bold')+str(len(uniq_wlist))+font.color('end')+'/'+font.color('bold')+str(len(uniq_subdomain))+font.color('end')\
	+' subdomain(s) are in wordlist.'
	return report
