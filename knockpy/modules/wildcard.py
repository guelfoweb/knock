import json
import header
import socket
import random

''' set the default timeout on sockets to 5 seconds '''
if hasattr(socket, 'setdefaulttimeout'): socket.setdefaulttimeout(5)

def rnd(alphabet):
	min       = 5
	max       = 15
	total     = 2
	random_string = ''
	for count in xrange(1, total):
		for x in random.sample(alphabet,random.randint(min,max)):
			random_string += x
	return random_string

def test_wildcard(target):
	random_string = rnd('abcdefghijklmnopqrstuvwxyz')
	random_subdomain = str(random_string)+'.'+target

	response = {}
	http_response = {}

	try:
		host = socket.gethostbyname(random_subdomain)
		if host:
			http_response = header.header(random_subdomain)
			http_response = json.loads(http_response)
			code = http_response['status']['code']
			try:
				content_length = str(http_response['http_headers']['content-length'])
			except:
				content_length = ''
			response.update({'test_target': random_subdomain, \
							'enabled': True, 'detected': \
							{'status_code': code, 'content_length': content_length}, \
							'http_response': http_response})
	except:
		response = {'test_target': random_subdomain, 'enabled': False, \
					'detected': {}, 'http_response': http_response}

	response = json.dumps(response, indent=4, separators=(',', ': '))
	return response

