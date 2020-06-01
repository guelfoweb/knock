==========================
Knock Subdomain Scan v.4.1.1
==========================

**Knockpy** is a python tool designed to enumerate subdomains on a target domain through a wordlist. It is designed to scan for **DNS zone transfer** and to try to bypass the **wildcard DNS record** automatically if it is enabled. Now knockpy supports queries to VirusTotal subdomains, you can setting the API_KEY within the config.json file.

.. image:: https://www.paypalobjects.com/en_US/IT/i/btn/btn_donateCC_LG.gif
   :target: https://www.paypal.com/cgi-bin/webscr?cmd=_s-xclick&hosted_button_id=LWNAWQ9G6APU2

**Very simply**

.. code-block:: 
  
  $ knockpy domain.com

.. figure:: https://user-images.githubusercontent.com/41558/29026398-dcd76fba-7b7b-11e7-9aa8-344637522c76.png
   :align: center
   :width: 90%
   :figwidth: 85%

**Export full report in JSON**

If you want to save full log `like this one <http://pastebin.com/d9nMiyP4>`_ just type:

.. code-block:: 

  $ knockpy domain.com --json

=======
Install
=======

**Prerequisites**

- Python 2.7.6

**Dependencies**

- Dnspython

.. code-block:: 
  
  $ sudo apt-get install python-dnspython
  

**Installing**

.. code-block::

  $ git clone https://github.com/guelfoweb/knock.git
  
  $ cd knock
  
  Set your virustotal API_KEY:
  
  $ nano knockpy/config.json
  
  $ sudo python setup.py install

Note that it's recommended to use `Google DNS <https://developers.google.com/speed/public-dns/docs/using>`_: 8.8.8.8 and 8.8.4.4

Knockpy arguments
-----

.. code-block:: 

  $ knockpy -h
  usage: knockpy [-h] [-v] [-w WORDLIST] [-r] [-c] [-j] domain
  
  ___________________________________________
  
  knock subdomain scan
  knockpy v.4.1
  Author: Gianni 'guelfoweb' Amato
  Github: https://github.com/guelfoweb/knock
  ___________________________________________
  
  positional arguments:
    domain         target to scan, like domain.com
  
  optional arguments:
    -h, --help      show this help message and exit
    -v, --version   show program's version number and exit
    -w WORDLIST     specific path to wordlist file
    -r, --resolve   resolve ip or domain name
    -c, --csv       save output in csv
    -f, --csvfields add fields name to the first row of csv output file
    -j, --json      export full report in JSON
  
  example:
    knockpy domain.com
    knockpy domain.com -w wordlist.txt
    knockpy -r domain.com or IP
    knockpy -c domain.com
    knockpy -j domain.com

For virustotal subdomains support you can setting your API_KEY in the config.json file.


Example
-------

**Subdomain scan with internal wordlist**

.. code-block::

  $ knockpy domain.com

**Subdomain scan with external wordlist**

.. code-block:: 

  $ knockpy domain.com -w wordlist.txt

**Resolve domain name and get response headers**

.. code-block:: 

  $ knockpy -r domain.com [or IP]

.. code-block::

	+ checking for virustotal subdomains: YES
	[
		"partnerissuetracker.corp.google.com",
		"issuetracker.google.com",
		"r5---sn-ogueln7k.c.pack.google.com",
		"cse.google.com",

		.......too long.......

		"612.talkgadget.google.com",
		"765.talkgadget.google.com",
		"973.talkgadget.google.com"
	]
	+ checking for wildcard: NO
	+ checking for zonetransfer: NO
	+ resolving target: YES
	{
		"zonetransfer": {
		    "enabled": false,
		    "list": []
		},
		"target": "google.com",
		"hostname": "google.com",
		"virustotal": [
		    "partnerissuetracker.corp.google.com",
		    "issuetracker.google.com",
		    "r5---sn-ogueln7k.c.pack.google.com",
		    "cse.google.com",
		    "mt0.google.com",
		    "earth.google.com",
		    "clients1.google.com",
		    "pki.google.com",
		    "www.sites.google.com",
		    "appengine.google.com",
		    "fcmatch.google.com",
		    "dl.google.com",
		    "translate.google.com",
		    "feedproxy.google.com",
		    "hangouts.google.com",
		    "news.google.com",

		    .......too long.......

		    "100.talkgadget.google.com",
		    "services.google.com",
		    "301.talkgadget.google.com",
		    "857.talkgadget.google.com",
		    "600.talkgadget.google.com",
		    "992.talkgadget.google.com",
		    "93.talkgadget.google.com",
		    "storage.cloud.google.com",
		    "863.talkgadget.google.com",
		    "maps.google.com",
		    "661.talkgadget.google.com",
		    "325.talkgadget.google.com",
		    "sites.google.com",
		    "feedburner.google.com",
		    "support.google.com",
		    "code.google.com",
		    "562.talkgadget.google.com",
		    "190.talkgadget.google.com",
		    "58.talkgadget.google.com",
		    "612.talkgadget.google.com",
		    "765.talkgadget.google.com",
		    "973.talkgadget.google.com"
		],
		"alias": [],
		"wildcard": {
		    "detected": {},
		    "test_target": "eqskochdzapjbt.google.com",
		    "enabled": false,
		    "http_response": {}
		},
		"ipaddress": [
		    "216.58.205.142"
		],
		"response_time": "0.0351989269257",
		"http_response": {
		    "status": {
		        "reason": "Found",
		        "code": 302
		    },
		    "http_headers": {
		        "content-length": "256",
		        "location": "http://www.google.it/?gfe_rd=cr&ei=60WIWdmnDILCXoKbgfgK",
		        "cache-control": "private",
		        "date": "Mon, 07 Aug 2017 10:50:19 GMT",
		        "referrer-policy": "no-referrer",
		        "content-type": "text/html; charset=UTF-8"
		    }
		}
	}



**Save scan output in CSV**

.. code-block:: 

  $ knockpy -c domain.com

**Export full report in JSON**

.. code-block:: 

  $ knockpy -j domain.com


==========
Talk about
==========


`100 Hacking Tools and Resources <https://www.hackerone.com/blog/100-hacking-tools-and-resources>`_ HackerOne.

`Ethical Hacking and Penetration Testing Guide <http://www.amazon.com/Ethical-Hacking-Penetration-Testing-Guide/dp/1482231611>`_ Book by Rafay Baloch.

Knockpy comes pre-installed on the following security distributions for penetration test:

- `BackBox Linux <http://www.backbox.org/>`_
- `PentestBox for Windows <https://pentestbox.org/>`_
- `Buscador Investigative Operating System <https://inteltechniques.com/buscador/>`_

=====
Other
=====

This tool is currently maintained by `Gianni 'guelfoweb' Amato <http://guelfoweb.com/>`_, who can be contacted at guelfoweb@gmail.com or twitter `@guelfoweb <http://twitter.com/guelfoweb>`_. Suggestions and criticism are welcome.
