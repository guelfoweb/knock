import json
import socket

''' set the default timeout on sockets to 5 seconds '''
if hasattr(socket, 'setdefaulttimeout'): socket.setdefaulttimeout(5)

try:
	import dns.resolver, dns.query, dns.zone
except:
	exit('ImportError: No module named python-dnspython\npip install dnspython')


def zonetransfer(target):
	zonetransfer_list = []
	my_resolver = dns.resolver.Resolver()
	my_resolver.timeout=2.0
	my_resolver.lifetime=2.0
	try:
		answers = my_resolver.query(target,'NS')
	except: 
		response = {'enabled': False, 'list': [] }
		response = json.dumps(response, indent=4, separators=(',', ': '))
		return response
	
	ip_from_nslist = []
	for name_server in answers:
		name_server = str(name_server).rstrip('.')
		try:
			ip_from_nslist.append(socket.gethostbyname(name_server))
		except socket.gaierror: # skip non resolvable name server
			pass

	for ip_from_ns in ip_from_nslist:
		zone = False

		try:
			zone = dns.zone.from_xfr(dns.query.xfr(ip_from_ns, target, timeout = 1))
		except: 
			pass
		
		if zone:
			for name, node in zone.nodes.items():
				rdataset = node.rdatasets
				for record in rdataset:
					name = str(name)
					if name != '@' and name != '*':
						zonetransfer_list.append(name+'.'+target)
	
	if zonetransfer_list:
		zonetransfer_list = [item.lower() for item in zonetransfer_list]
		zonetransfer_list = list(set(zonetransfer_list))
		response = {'enabled': True, 'list': zonetransfer_list }
		response = json.dumps(response, indent=4, separators=(',', ': '))
		return response
	else:
		response = {'enabled': False, 'list': [] }
		response = json.dumps(response, indent=4, separators=(',', ': '))
		return response
