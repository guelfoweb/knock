from censys.search import CensysCertificates

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
# plugin: api_censys
# version: 1.0

def get(domain):
	# censys -> object -> CensysSearchAPIv1.search: key -> parsed.names

	# https://search.censys.io/account/api
	api_id = "" # <- 0d2bc370-8922-4e42-aeee-c33b41d30a74
	api_secret = "" # <- FMKul1AbqteiVzzjGXFN55vFfNG6ZMB5
	limit = 1000

	certificates = CensysCertificates(api_id=api_id, api_secret=api_secret)
	query = "parsed.names: {domain}".format(domain=domain)
	data = certificates.search(query, fields=["parsed.names"], max_records=limit)
	
	result = []
	for item in data:
		subdomains = item["parsed.names"]
		for subdomain in subdomains:
			if subdomain.endswith(domain) and subdomain not in result:
					result.append(subdomain)

	return result
