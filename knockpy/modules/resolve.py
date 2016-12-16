import json
import header
import socket
import time
#import zonetransfer

''' set the default timeout on sockets to 5 seconds '''
if hasattr(socket, 'setdefaulttimeout'): socket.setdefaulttimeout(5)

def resolve(target):
	hostname = ''
	aliaslist = []
	ipaddrlist = []
	code = ''
	header_response = {}
	iplist = []
	response = {}
	#zonetransfer_json = {}
	
	time_start = time.time()
	try:
		soc = socket.gethostbyname_ex(target)
		#zonetransfer_json = json.loads(zonetransfer.zonetransfer(target))

		if soc:
			hostname = soc[0]
			aliaslist = soc[1]
			ipaddrlist = soc[2]

			'''
			check for http headers
			'''
			try:
				header_response = json.loads(header.header(target))
				code = header_response['status']['code']
			except:
				header_response = {}
				code = ''

			if hostname != target:
				header_response = json.loads(header.header(hostname))
			
			time_end = time.time()
	except:
		time_end = time.time()
	
	response_time = str(time_end-time_start)

	response = {'target': target, 'hostname': hostname, \
				'alias': aliaslist, 'ipaddress': ipaddrlist, \
				'status': code, 'response_time': response_time, \
				'http_response': header_response} #, 'zonetransfer': zonetransfer_json}

	response = json.dumps(response, indent=4, separators=(',', ': '))
	return response	
