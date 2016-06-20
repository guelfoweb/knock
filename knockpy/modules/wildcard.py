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

import random
import socket
from knockpy.modules import getheader


def bypass(target, wcode):
    # beta feature
    header = getheader.req(target, '/', 'HEAD')
    # bypass status code -> header[0] = 301 or 302
    if header and str(header[0]) != wcode:
        return True
    else:
        return False


def test(target):
    # call from show_wildcard(domain)
    rndString = rnd('abcdefghijklmnopqrstuvwxyz')
    rndSubdomain = str(rndString) + '.' + target
    try:
        host = socket.gethostbyname(rndSubdomain)
        if host:
            httpreq = getheader.req(rndSubdomain, '/', 'HEAD')
            return httpreq, True
    except:
        return False, False


def rnd(alphabet):  # random string
    # alphabet  = 'abcdefghijklmnopqrstuvwxyz'
    min_value = 5
    max_value = 15
    total = 2
    rndstring = ''
    for count in xrange(1, total):
        for x in random.sample(alphabet, random.randint(min_value, max_value)):
            rndstring+=x
    return rndstring
