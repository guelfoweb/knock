import requests
import bs4

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
# plugin: rapiddns
# version: 1.0

def get(domain):
	# rapiddns -> TABLE -> scraping 'td'
	url = "https://rapiddns.io/subdomain/{domain}#result".format(domain=domain)
	resp = requests.get(url, timeout=5).text
	soup = bs4.BeautifulSoup(resp, "html.parser")

	result = []
	for item in soup.find_all("td"):
		subdomain = item.text
		if subdomain.endswith(domain):
			result.append(subdomain)

	return result