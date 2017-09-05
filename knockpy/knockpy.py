#!/usr/bin/env python
# -*- coding: utf-8 -*-

from modules import zonetransfer
from modules import header
from modules import resolve
from modules import wildcard
from modules import save_report
from modules import virustotal_subdomains

from urlparse import urlparse

import sys
import json
import os.path
import datetime
import argparse

__author__='Gianni \'guelfoweb\' Amato'
__version__='4.1.1'
__url__='https://github.com/guelfoweb/knock'
__description__='''\
___________________________________________

knock subdomain scan
knockpy v.'''+__version__+'''
Author: '''+__author__+'''
Github: '''+__url__+'''
___________________________________________
'''
__epilog__='''
example:
  knockpy domain.com
  knockpy domain.com -w wordlist.txt
  knockpy -r domain.com or IP
  knockpy -c domain.com
  knockpy -j domain.com

For virustotal subdomains support you can setting your API KEY in the
config.json file.
 
'''

def loadfile_wordlist(filename):
	filename = open(filename,'r')
	wlist = filename.read().split('\n')
	filename.close
	return filter(None, wlist)

def print_header():
	print """
  _  __                 _                
 | |/ /                | |   """+__version__+"""            
 | ' / _ __   ___   ___| | ___ __  _   _ 
 |  < | '_ \ / _ \ / __| |/ / '_ \| | | |
 | . \| | | | (_) | (__|   <| |_) | |_| |
 |_|\_\_| |_|\___/ \___|_|\_\ .__/ \__, |
                            | |     __/ |
                            |_|    |___/ 
"""

def print_header_scan():
	print '\nIp Address\tStatus\tType\tDomain Name\t\t\tServer'
	print '----------\t------\t----\t-----------\t\t\t------'

def get_tab(string):
		if len(str(string)) > 23:
			return '\t'
		elif len(str(string)) > 15 and len(str(string)) <= 23:
			return '\t\t'
		else:
			return '\t\t\t'

subdomain_csv_list = []
def print_output(data):
	if data['alias']:
		
		for alias in data['alias']:
			ip_alias = data['ipaddress'][0]
			try:
				server_type = str(data['http_response']['http_headers']['server'])
			except:
				server_type = ''

			row = ip_alias+'\t'+str(data['status'])+'\t'+'alias'+'\t'+str(alias)+get_tab(alias)+str(server_type)
			print (row)
			subdomain_csv_list.append(ip_alias+','+str(data['status'])+','+'alias'+','+str(alias)+','+str(server_type))
		
		for ip in data['ipaddress']:
			try:
				server_type = str(data['http_response']['http_headers']['server'])
			except:
				server_type = ''

			row = ip+'\t'+str(data['status'])+'\t'+'host'+'\t'+str(data['hostname'])+get_tab(data['hostname'])+str(server_type)
			print (row)
			subdomain_csv_list.append(ip+','+str(data['status'])+','+'host'+','+str(data['hostname'])+','+str(server_type))
	else:
		
		for ip in data['ipaddress']:
			try:
				server_type = str(data['http_response']['http_headers']['server'])
			except:
				server_type = ''

			row = ip+'\t'+str(data['status'])+'\t'+'host'+'\t'+str(data['hostname'])+get_tab(data['hostname'])+str(server_type)
			print (row)
			subdomain_csv_list.append(ip+','+str(data['status'])+','+'host'+','+str(data['hostname'])+','+str(server_type))

def init(text, resp=False):
	if resp:
		print(text)
	else:
		print(text),

def main():
	parser = argparse.ArgumentParser(
		version=__version__,
		formatter_class=argparse.RawTextHelpFormatter,
		prog='knockpy',
		description=__description__,
		epilog = __epilog__)

	parser.add_argument('domain', help='target to scan, like domain.com')
	parser.add_argument('-w', help='specific path to wordlist file',
					nargs=1, dest='wordlist', required=False)
	parser.add_argument('-r', '--resolve', help='resolve single ip or domain name',
						action='store_true', required=False)
	parser.add_argument('-c', '--csv', help='save output in csv',
						action='store_true', required=False)
	parser.add_argument('-f', '--csvfields', help='add fields name to the first row of csv output file',
						action='store_true', required=False)
	parser.add_argument('-j', '--json', help='export full report in JSON',
						action='store_true', required=False)

						
	args = parser.parse_args()
	
	target = args.domain
	wlist = args.wordlist
	resolve_host = args.resolve
	save_scan_csv = args.csv
	save_scan_csvfields = args.csvfields
	save_scan_json = args.json

	print_header()

	'''
	start
	'''
	time_start = str(datetime.datetime.now())

	'''
	parse target domain
	'''
	if target.startswith("http") or target.startswith("ftp"):
		parsed_uri = urlparse(target)
		target = '{uri.netloc}'.format(uri=parsed_uri)

	'''
	check for virustotal subdomains
	'''
	init('+ checking for virustotal subdomains:', False)
	subdomain_list = []

	_ROOT = os.path.abspath(os.path.dirname(__file__))
	config_file = os.path.join(_ROOT, '', 'config.json')

	if os.path.isfile(config_file):
		with open(config_file) as data_file:    
			apikey = json.load(data_file)
			try:
				apikey_vt = apikey['virustotal']
				if apikey_vt != '':
					virustotal_list = virustotal_subdomains.get_subdomains(target, apikey_vt)
					if virustotal_list:
						init('YES', True)
						print(json.dumps(virustotal_list, indent=4, separators=(',', ': ')))
						for item in virustotal_list:
							subdomain = item.replace('.'+target, '')
							if subdomain not in subdomain_list:
								subdomain_list.append(subdomain)
					else:
						init('NO', True)
				else:
					init('SKIP', True)
					init('\tVirusTotal API_KEY not found', True)
					virustotal_list = []
			except:
				init('SKIP', True)
				init('\tVirusTotal API_KEY not found', True)
				virustotal_list = []
	else:
		init('SKIP', True)
		init('\tCONFIG FILE NOT FOUND', True)
		virustotal_list = []

	'''
	check for wildcard
	'''
	init('+ checking for wildcard:', False)
	wildcard_json = json.loads(wildcard.test_wildcard(target))
	if wildcard_json['enabled']:
		init('YES', True)
		print(json.dumps(wildcard_json['detected'], indent=4, separators=(',', ': ')))
	else:
		init('NO', True)

	'''
	check for zonetransfer
	'''
	init('+ checking for zonetransfer:', False)
	zonetransfer_json = json.loads(zonetransfer.zonetransfer(target))
	if zonetransfer_json['enabled']:
		init('YES', True)
		print(json.dumps(zonetransfer_json['list'], indent=4, separators=(',', ': ')))
		for item in zonetransfer_json['list']:
			subdomain = item.replace('.'+target, '')
			if subdomain not in subdomain_list:
				subdomain_list.append(subdomain)
	else:
		init('NO', True)
		
	'''
	optional argument -w WORDLIST
	'''
	if wlist: 
		wordlist = wlist[0]
	else:
		_ROOT = os.path.abspath(os.path.dirname(__file__))
		wordlist = os.path.join(_ROOT, 'wordlist', 'wordlist.txt')
	
	if not os.path.isfile(wordlist): 
		exit('File not found: ' + wordlist)
	
	word_list = loadfile_wordlist(wordlist)
	word_list = [item.lower() for item in word_list]
	subdomain_list = subdomain_list + word_list
	subdomain_list = list(set(subdomain_list))
	subdomain_list = sorted(subdomain_list)
	wordlist_count = len(subdomain_list)
	
	'''
	resolve domain
	'''
	init('+ resolving target:', False)
	response_resolve = json.loads(resolve.resolve(target))
	response_resolve.update({'wildcard': wildcard_json, 'zonetransfer': zonetransfer_json, 'virustotal': virustotal_list})
	response_resolve['ipaddress']
	if response_resolve['hostname']:
		init('YES', True)
	else:
		init('NO', True)
	
	ip_list = []
	try:
		del response_resolve['status']
		for ip in response_resolve['ipaddress']:
			ip_list.append(ip)
	except:
		pass
	
	time_end = str(datetime.datetime.now())
	
	stats = {'time_start': time_start, 'time_end': time_end}

	'''
	optional argument -r RESOLVE DOMAIN
	'''
	if resolve_host: 
		response_resolve = json.dumps(response_resolve, indent=4, separators=(',', ': '))
		print(response_resolve)
		exit()
	
	'''
	scan for subdomain
	'''
	init('- scanning for subdomain...', True)
		
	print_header_scan()

	subdomains_json_list = []

	import sys
	for item in subdomain_list:
		sys.stdout.write("%s\r" % item)
		sys.stdout.flush()
		subdomain_target = item+'.'+target
		subdomain_resolve = json.loads(resolve.resolve(subdomain_target))

		if subdomain_resolve['hostname']:
			try:
				status_code = subdomain_resolve['http_response']['status']['code']
			except:
				status_code = ''

			if wildcard_json['enabled']:
				wildcard_code = wildcard_json['detected']['status_code']
				if str(status_code) != '' and str(wildcard_code) != '' and str(status_code) == str(wildcard_code):
					try:
						content_length = str(subdomain_resolve['http_response']['http_headers']['content-length'])
					except:
						content_length = ''
					try:
						wildcard_content_length = wildcard_json['http_response']['http_headers']['content-length']
					except:
						wildcard_content_length = ''
					'''
					Experimental:
					content_length == '0' => This is a work around.
					'''
					if content_length == '0' or str(content_length) == str(wildcard_content_length):
						pass
					else:
						print_output(subdomain_resolve)
						subdomains_json_list.append(subdomain_resolve)
				else:
					print_output(subdomain_resolve)
					subdomains_json_list.append(subdomain_resolve)
			else:
				print_output(subdomain_resolve)
				subdomains_json_list.append(subdomain_resolve)		
		sys.stdout.write("%s\r" % ('                               ') )
		sys.stdout.flush()

	subdomain_found = []
	for items in subdomains_json_list:
		try:
			del items['status']
		except:
			pass
		
		if items['hostname'] not in subdomain_found:
			subdomain_found.append(str(items['hostname']))

		for item in items['alias']:
			if item not in subdomain_found:
				subdomain_found.append(str(item))

		for item in items['ipaddress']:
			ip_list.append(str(item))

	ipaddr_list = list(set(ip_list))
	ip_count = len(ipaddr_list)
	subdomain_found = list(set(subdomain_found))
	sub_count = len(subdomain_found)
	
	'''
	optional argument -s SAVE FULL SCAN REPORT
	'''

	stats = {'time_start': time_start, 'time_end': time_end, \
			'sub_count': sub_count, 'ip_count': ip_count, \
			'wordlist': {'filename': wordlist, 'item_count': wordlist_count}, \
			'knockpy': {'version': __version__, 'query': sys.argv, 'url': __url__}}

	try:
		del resolve_host_report['stats']
	except:
		pass

	if not resolve_host:
		if save_scan_csv:
			exit(save_report.export(target, subdomain_csv_list, 'csv'))
		elif save_scan_csvfields:
			exit(save_report.export(target, subdomain_csv_list, 'csv', save_scan_csvfields))
		elif save_scan_json:
			report_json = {'target_response': response_resolve, \
							'subdomain_response': subdomains_json_list, \
							'found': {'ipaddress': ipaddr_list, \
							'subdomain': subdomain_found, \
							'csv': subdomain_csv_list}, 'info': stats}
			report_json = json.dumps(report_json, indent=4, separators=(',', ': '))
			exit(save_report.export(target, report_json, 'json'))
		else:
			exit()

if __name__ == '__main__':
	main()
