==========================
Knock Subdomain Scan v.4.0beta
==========================

Knockpy is a python tool designed to enumerate subdomains on a target domain through a wordlist.

**Very simply**

.. code-block:: 
  
  $ knockpy domain.com

.. figure:: https://cloud.githubusercontent.com/assets/41558/21270690/f8854cb8-c3b7-11e6-933b-c47e358f4a70.png
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
  

**Install from pypi**

.. code-block::

  $ sudo pip install https://github.com/guelfoweb/knock/archive/knock4.zip

**Install manually**

`Download zip <https://github.com/guelfoweb/knock/archive/knock4.zip>`_ and extract folder:

.. code-block:: 

  $ cd knock-knock4/

  $ sudo python setup.py install

Note that it's recommended to use `google dns <https://developers.google.com/speed/public-dns/docs/using>`_: 8.8.8.8 and 8.8.4.4

Knockpy arguments
-----

.. code-block:: 

  $ knockpy -h
  usage: knockpy [-h] [-v] [-w WORDLIST] [-r] [-c] [-j] domain
  
  ___________________________________________
  
  knock subdomain scan
  knockpy v.4.0beta
  Author: Gianni 'guelfoweb' Amato
  Github: https://github.com/guelfoweb/knock
  ___________________________________________
  
  positional arguments:
    domain         target to scan, like domain.com
  
  optional arguments:
    -h, --help     show this help message and exit
    -v, --version  show program's version number and exit
    -w WORDLIST    specific path to wordlist file
    -r, --resolve  resolve ip or domain name
    -c, --csv      save output in csv
    -j, --json     export full report in JSON
  
  example:
    knockpy domain.com
    knockpy domain.com -w wordlist.txt
    knockpy -r domain.com or IP
    knockpy -c domain.com
    knockpy -j domain.com


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
      "alias": [],
      "wildcard": {
          "detected": {},
          "test_target": "kfwpsxvdnt.google.com",
          "enabled": false,
          "http_response": {}
      },
      "ipaddress": [
          "216.58.205.142"
      ],
      "response_time": "0.0917398929596",
      "http_response": {
          "status": {
              "reason": "Found",
              "code": 302
          },
          "http_headers": {
              "date": "Thu, 22 Dec 2016 09:28:48 GMT",
              "content-length": "256",
              "content-type": "text/html; charset=UTF-8",
              "location": "http://www.google.it/?gfe_rd=cr&ei=0JxbWIGmLofCXruVhcgI",
              "cache-control": "private"
          }
      }
  }


**Save output in csv**

.. code-block:: 

  $ knockpy -c domain.com

**Export full report in JSON**

.. code-block:: 

  $ knockpy -j domain.com


==========
Talk about
==========

`Ethical Hacking and Penetration Testing Guide <http://www.amazon.com/Ethical-Hacking-Penetration-Testing-Guide/dp/1482231611>`_ Book by Rafay Baloch.

Knockpy comes pre-installed on the following security distributions for penetration test:

- `BackBox Linux <http://www.backbox.org/>`_
- `PentestBox for Windows <https://pentestbox.org/>`_

=====
Other
=====

This tool is currently maintained by Gianni 'guelfoweb' Amato, who can be contacted at guelfoweb@gmail.com or twitter `@guelfoweb <http://twitter.com/guelfoweb>`_. Suggestions and criticism are welcome.

Sponsored by `Security Side <http://www.securityside.it/>`_
