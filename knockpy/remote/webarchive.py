import requests
import re

"""
Let's start with simple function specifications:

1. if apikey is required, use "api_" before the plugin name:

	api_service.py

2. the function name must be "get" and take as parameter "domain":

	def get(domain):
		foo

3. the function must return a possibly unique list of subdomains:

	['sub1.domain.com', 'sub2.domain.com']

4. to parse the results it is recommended to use the standard modules such as:

	requests, json, bs4, re
"""

# author: Gianni Amato
# plugin: archive
# version: 1.0

def get(domain):
	# webarchive -> TEXT URL LIST -> match subdomain
	url = "https://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=txt&fl=original&collapse=urlkey".format(domain=domain)
	resp = requests.get(url, timeout=5).text

	result = []
	pattern = "http(s)?:\/\/(.*\.%s)" % domain
	for item in resp.split('\n'):
		match = re.match(pattern, item)

		if match and re.match("^[a-zA-Z0-9-\.]*$", match.groups()[1]):
			subdomain = match.groups()[1]
			if subdomain not in result:
				result.append(subdomain)
	
	return result
