#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Knock subdomain scan (aka knockpy)
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

from modules import core
import argparse

__version__='3.0'
__description__='''\
  ___________________________________________

  knock subdomain scan (aka knockpy) | v.'''+__version__+'''
  Author: Gianni 'guelfoweb' Amato
  Github: https://github.com/guelfoweb/knock
  ___________________________________________
'''

def getinfo(domain, resolve):
	# Resolve domain
	core.header_target(domain)
	# if [knockpy domain.com] -> resolve is False
	# if [knockpy -r domain.com] -> resolve is True
	core.show_resolved(domain,resolve)

	# Status code
	core.header_response_code()
	core.get_banner(domain)
	core.show_banner('code')

	# Headers
	core.header_response_head()
	core.show_banner('head')

	# Wildcard
	core.show_wildcard(domain)

def get_wordlist_targetlist(domain, path_to_worlist=False):
	# Wordlist, targetlist
	core.get_wordlist(domain, path_to_worlist)
	core.get_targetlist(domain)

def start(domain):
	# Start
	core.header_start_scan(domain)
	core.subdomain_scan()

def statistics():
	# Statistics
	core.header_stats_summary()
	core.report()

def savescan(domain, filename=None):
	# Save result
	core.save_in_csv(domain, filename)

def getzone(domain):
	core.getzone(domain)

def main():
	parser = argparse.ArgumentParser(
		version=__version__,
		formatter_class=argparse.RawTextHelpFormatter,
		prog='knockpy',
		description=__description__,
		epilog = '''\
EXAMPLE:

subdomain scan with internal wordlist
  knockpy domain.com

resolve domain name and get response headers
  knockpy -r domain.com

check zone transfer for domain name
  knockpy -z domain.com

The ALIAS name is marked in yellow''')

	parser.add_argument('domain', help='specific target domain, like domain.com')

	parser.add_argument('-w', help='specific path to wordlist file',
						nargs=1, dest='wordlist', required=False)

	parser.add_argument('-r', '--resolve', help='resolve ip or domain name',
						action='store_true', required=False)

	parser.add_argument('-z', '--zone', help='check for zone transfer',
						action='store_true', required=False)

	parser.add_argument('-o', '--output', help='output filename', nargs=1, required=False)

	args = parser.parse_args()

	# args strings
	domain = args.domain
	wlist = args.wordlist
	filename = args.output
	if filename: filename = filename[0]
	if wlist: wlist = wlist[0]

	# args True or False
	resolve = args.resolve
	zone = args.zone

	# [knockpy -r domain.com]
	if domain and resolve and not zone:
		# resolve = True
		getinfo(domain, resolve)

	# [knockpy -z domain.com]
	elif domain and zone and not resolve:
		getzone(domain)

	# [knockpy domain.com]
	elif domain and not resolve and not zone:
		# resolve = False
		getinfo(domain, resolve)

		if wlist:
			get_wordlist_targetlist(domain, wlist)
		else:
			# get_wordlist_targetlist(domain,path_to_worlist=False)
			# no wlist
			get_wordlist_targetlist(domain)

		start(domain)
		statistics()
		savescan(domain, filename)

	else:
		exit('error arguments: use knockpy -h to help')

if __name__ == '__main__':
	main()
