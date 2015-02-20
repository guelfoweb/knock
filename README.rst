==========================
knock Subdomain Scan v.3.0
==========================

Knock is a python tool designed to enumerate subdomains on a target domain through a wordlist.

Usage
-----

.. code-block:: bash

  knockpy [-h] [-v] [-w WORDLIST] [-r] [-z] domain

positional arguments:

.. code-block:: bash

  domain         specific target domain, like domain.com

optional arguments:

.. code-block:: bash

  -h, --help     show this help message and exit
  -v, --version  show program's version number and exit
  -w WORDLIST    specific path to wordlist file
  -r, --resolve  resolve ip or domain name
  -z, --zone     check for zone transfer

Example
-------

subdomain scan with internal wordlist

.. code-block:: bash

  knockpy domain.com

subdomain scan with external wordlist

.. code-block:: bash

  knockpy domain.com -w wordlist.txt

resolve domain name and get response headers

.. code-block:: bash

  knockpy domain.com -r domain.com

check zone transfer for domain name

.. code-block:: bash

  knockpy domain.com -z domain.com

Note
----

The ALIAS name is marked in yellow.

=======
Install
=======

Prerequisites
-------------

.. code-block:: bash

Python 2.6.5 -> 2.7.x

Install
-------

from pypi

.. code-block:: bash

sudo pip install https://github.com/guelfoweb/knock/archive/knock3.zip

manually download and install

.. code-block:: bash

<a href="https://github.com/guelfoweb/knock/archive/knock3.zip" alt="knock-knock3.zip" title="knock-knock3.zip">Download Zip</a> and extract knock-knock3 folder

.. code-block:: bash

cd knock-knock3/

.. code-block:: bash

sudo python setup.py install

Note
----

Is recommended to use <a href="https://developers.google.com/speed/public-dns/docs/using">Google DNS</a> <code>8.8.8.8</code> | <code>8.8.4.4</code>

==========
Talk about
==========

<ul>
<li><a href="http://www.amazon.com/Ethical-Hacking-Penetration-Testing-Guide/dp/1482231611">Ethical Hacking and Penetration Testing Guide</a> <i>Book by Rafay Baloch</i></li>
</ul>

Other
=====

This tool is currently maintained by Gianni 'guelfoweb' Amato, who can be contacted at guelfoweb@gmail.com or twitter <a href="http://twitter.com/guelfoweb">@guelfoweb</a>. Suggestions and criticism are welcome.

Sponsored by **<a href="http://www.securityside.it/">Security Side</a>**.
