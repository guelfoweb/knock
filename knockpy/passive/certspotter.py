import requests
import json

"""
Let's start with simple function specifications:

1. the function name must be "get" and take as parameter "domain":

	def get(domain):
		foo

2. the function must return a possibly unique list of subdomains:

	['sub1.domain.com', 'sub2.domain.com']

3. to parse the results it is recommended to use the standard modules such as:

	requests, json, bs4, re
"""

# author: Gianni Amato
# plugin: certspotter
# version: 1.0

def get(domain):
	# certspotter -> LIST -> JSON: key -> dns_names
	url = "https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names".format(domain=domain)
	resp = requests.get(url).text
	
	resp = json.loads(resp)

	result = []
	for item in resp:
		for subdomain in item['dns_names']:
			if subdomain not in result:
				result.append(subdomain)

	return result