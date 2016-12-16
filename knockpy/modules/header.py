import json
import httplib

def header(url, path='/', method='HEAD'):
	headers = {}
	response = {}
	user_agent = "Mozilla/5.0 (X11; Ubuntu; Linux i686; rv:35.0) Gecko/20100101 Firefox/35.0"
	try:
		conn = httplib.HTTPConnection(url)
		conn.putrequest(method, path)
		conn.putheader("User-Agent", user_agent)
		conn.endheaders()
		res = conn.getresponse()
		conn.close()
		for item in res.getheaders():
			headers.update({item[0]: item[1]})
			
		response = {'status': {'code': res.status, 'reason': res.reason}, 'http_headers': headers}
		response = json.dumps(response, indent=4, separators=(',', ': '))
	except:
		response = {}
	
	return response
