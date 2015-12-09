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

import utilipy
import font
import os

_ROOT = os.path.abspath(os.path.dirname(__file__))
def get_data(path):
	return os.path.join(_ROOT, 'wordlist', path)

internal_wlist = get_data('wordlist.txt').replace('modules/', '')
remote_wlist = 'https://raw.github.com/guelfoweb/knock/master/wordlist.txt'

def check_status(path_to_wordlist=False):
	if path_to_wordlist:
		local_wlist=path_to_wordlist
	else:
		local_wlist=internal_wlist
	if utilipy.isfile(local_wlist): # local wordlist
		wlist = utilipy.loadfile_wordlist(local_wlist)
		location = 'local'
	else: # remote wordlist
		print font.color('red')+'\nwarning: wordlist not found '+local_wlist+font.color('end')
		res = raw_input('\npress [c] to download remote wordlist or [enter] to exit: ')
		if res != 'c': exit()
		wlist = utilipy.downloadfile(remote_wlist)
		if wlist:
			wlist = wlist.split('\n')
			location = 'remote'
	
	if wlist and location:
		return location, filter(None, wlist)
	else:
		exit('Local wordlist not found\n'+local_wlist+'\n\nRemote wordlist not found or connection error\n'+remote_wlist)

def prepare(domain):
	wordlist = []
	get_info_wordlist = check_status()
	location = get_info_wordlist[0]
	wlist = get_info_wordlist[1]
		
	for sub in wlist:
		wordlist.append(sub+'.'+domain)
		
	return worlist
