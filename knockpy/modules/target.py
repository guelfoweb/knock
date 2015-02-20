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

import font
import subscan
import utilipy
import stats

global found
found = []
def get(target, verbose, test):
	text = ''
	result = subscan.start(target)
	if result: (alias, host) = result[0], result[1]
	else: return
		
	# Detect alias
	for item in alias:
		found.append([target, item[1], item[0], 'alias'])
		text += font.color('yellow') + str(item[1]).ljust(18) + str(item[0]) + font.color('end') + '\n'
		# Test wildcard to detect host
		if verbose and not test:
			for item in host:
				found.append([target, item[1], item[0], 'host'])
				text += str(item[1]).ljust(18) + str(item[0]) + '\n'

	# Test subdomain to detect host
	if not verbose and not test:
		for item in host:
			found.append([target, item[1], item[0], 'host'])
			text += str(item[1]).ljust(18) + str(item[0]) + '\n'

	# Test root domain to detect host
	if test:
		for item in host:
			found.append([target, item[1], item[0], 'host'])
			text += str(item[1]).ljust(18) + str(item[0]) + '\n'

	return text.rstrip()

def save_csv(domain):
	if not found: exit()
	timestamp = utilipy.timestamp()
	filename = domain.replace('.', '_')+'_'+str(timestamp)+'.csv'
	try:
		utilipy.touch(filename)
		with open(filename, 'a') as f:
			f.write('target,ip address,domain name,type\n')
			for row in found:
				f.write(row[0]+','+row[1]+','+row[2]+','+row[3]+'\n')
		f.close()
		return '\nOutput saved in CSV format: '+filename
	except: return '\nCannot write csv file: '+filename
	
def get_report(targetlist):
	return stats.cogito(found, targetlist)
