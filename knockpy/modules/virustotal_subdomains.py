import json

try:
	from urllib.parse import urlencode
	from urllib.request import urlopen
except ImportError:
	from urllib import urlencode
	from urllib import urlopen


def get_subdomains(domain, apikey):
	url = 'https://www.virustotal.com/vtapi/v2/domain/report'
	parameters = {'domain': domain, 'apikey': apikey}
	try:
		response = urlopen('%s?%s' % (url, urlencode(parameters))).read()
		response_dict = json.loads(response)
		return response_dict['subdomains']
	except:
		return False
