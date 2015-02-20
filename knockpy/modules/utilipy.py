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

import re
import os.path
import urllib2
import string
import time

''' v.0.1
	This module contains the following functions:
	. replace_url_to_link(text)
	. loadfile_wordlist(filename)
	. isfile(filename)
	. touch(filename)
	. downloadfile(fileurl)
	. timestamp()
	. uniqlist(lista)
 '''

def replace_url_to_link(text):
	# Replace url text to link.
	# Credit: https://gist.github.com/guillaumepiot/4539986
	urls = re.compile(r"((https?):((//)|(\\\\))+[\w\d:#@%/;$()~_?\+-=\\\.&]*)", re.MULTILINE|re.UNICODE)
	text = urls.sub(r'<a href="\1" target="_blank">\1</a>', text)
	''' Replace email to mailto '''
	urls = re.compile(r"([\w\-\.]+@(\w[\w\-]+\.)+[\w\-]+)", re.MULTILINE|re.UNICODE)
	text = urls.sub(r'<a href="mailto:\1">\1</a>', text)
	return text

def loadfile_wordlist(filename):
	# Load wordlist from file (rows read per fetched row) and return list.
	filename = open(filename,'r')
	wlist = filename.read().split('\n')
	filename.close
	return filter(None, wlist)
	
def isfile(filename):
	# Verify if file exist.
	return os.path.isfile(filename)

def touch(filename):
	# Create empty file.
	fname = filename
	file = open(fname, 'w')
	file.close()
	
def downloadfile(fileurl):
	# Get content remote file via http(s) and return contenet.
	try: 
		response = urllib2.urlopen(fileurl)
		return response.read()
	except: pass
	
def timestamp():
	return time.time()

def uniqlist(lista):
    ulist = []
    [ulist.append(x) for x in lista if x not in ulist]
    return ulist
