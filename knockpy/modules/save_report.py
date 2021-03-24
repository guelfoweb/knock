import time
import json

def touch(filename):
	fname = filename
	file = open(fname, 'w')
	file.close()

def export(domain, report, _type, fields=False):
	timestamp = time.time()
	filename = domain.replace('.', '_')+'_'+str(timestamp)+'.'+_type
	filename = '/tmp/' + filename
	if _type == 'csv':
		csv_report = ''
		if fields:
			csv_report += 'ip,status,type,domain_name,server\n'
		for item in report:
			csv_report += item + '\n'
		report = csv_report
	try:
		with open(filename, 'a') as f:
			f.write(report)
		f.close()
		r='\n'+_type.upper()+' report saved in: '+filename
		print(str(r))
		return r
	except:
		r='\nCannot write report file: '+filename
		print(str(r))
	return r
