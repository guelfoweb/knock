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

import httplib

agent = "Mozilla/5.0 (X11; Ubuntu; Linux i686; rv:35.0) Gecko/20100101 Firefox/35.0"

def req(url, path, method):
	try:
		conn = httplib.HTTPConnection(url)
		conn.putrequest(method, path)
		conn.putheader("User-Agent", agent)
		'''
		#conn.putheader("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
		#conn.putheader("Connection", "keep-alive")

		# Test for XST
		conn.putheader('Via', '<script>alert(0)</script>')
		conn.request(method, path)
		'''
		conn.endheaders()
		res = conn.getresponse()
		conn.close()
		return res.status, res.reason, res.getheaders()
	except:
		return False
