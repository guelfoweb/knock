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

from knockpy.modules import font


def status_wordlist(location, wlist):
    return font.color('ciano') + '\nLoaded ' + font.color('bold') + location + font.color('end')\
     + font.color('ciano') + ' wordlist with ' + font.color('bold') + str(len(wlist)) + font.color('end')\
     + font.color('ciano') + ' item(s)\n' + font.color('end')


def start_scan(domain):
    text = font.color('bold') + 'Getting subdomain for ' + domain + font.color('end') + '\n\n'
    text += 'Ip Address'.ljust(18) + 'Domain Name\n'
    text += '----------'.ljust(18) + '-----------'
    return text


def target(domain):
    text = font.color('bold') + 'Target information ' + domain + font.color('end') + '\n\n'
    text += 'Ip Address'.ljust(18) + 'Target Name\n'
    text += '----------'.ljust(18) + '-----------'
    return text


def response_code():
    text = 'Code'.ljust(18) + 'Reason\n'
    text+= '----------'.ljust(18) + '-----------'
    return text


def response_head():
    text = 'Field'.ljust(18) + 'Value\n'
    text+= '----------'.ljust(18) + '-----------'
    return text


def stats_summary():
    return font.color('bold') + '\nSummary\n' + font.color('end')


def start_scan_zt(domain):
    text = font.color('bold') + 'Getting zone transfer for ' + domain + font.color('end') + '\n\n'
    text+= 'Ip Address'.ljust(18) + 'Domain Name\n'
    text+= '----------'.ljust(18) + '-----------'
    return text
