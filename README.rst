==========================
Knock Subdomain Scan v.4.0
==========================

Knockpy is a python tool designed to enumerate subdomains on a target domain through a wordlist.

.. figure:: https://cloud.githubusercontent.com/assets/41558/6314173/d22644d6-b9d3-11e4-9e95-e3a72a946bcb.jpg
   :align: center
   :width: 90%
   :figwidth: 85%

Usage
-----

.. code-block:: bash

  knockpy [-h] [-v] [-w WORDLIST] [-r] [-c] [-j] domain

positional arguments:

.. code-block:: bash

  domain         specific target domain, like domain.com

optional arguments:

.. code-block:: bash

  -h, --help     show this help message and exit
  -v, --version  show program's version number and exit
  -w WORDLIST    specific path to wordlist file
  -r, --resolve  resolve ip or domain name
  -c, --csv      save output in CSV
  -j, --json     export full report in JSON


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

  knockpy -r domain.com [or IP]

save output in csv

.. code-block:: bash

  knockpy -c domain.com

export full report in JSON

.. code-block:: bash

  knockpy -j domain.com

=======
Install
=======

from pypi (as root)

.. code-block:: bash

  pip install https://github.com/guelfoweb/knock/archive/knock4.zip

or manually, `download zip <https://github.com/guelfoweb/knock/archive/knock4.zip>`_ and extract folder

.. code-block:: bash

  cd knock-knock4/

(as root)

.. code-block:: bash

  python setup.py install

note: tested with python 2.7.6 | is recommended to use `google dns <https://developers.google.com/speed/public-dns/docs/using>`_ (8.8.8.8 | 8.8.4.4)

==========
Talk about
==========

`Ethical Hacking and Penetration Testing Guide <http://www.amazon.com/Ethical-Hacking-Penetration-Testing-Guide/dp/1482231611>`_ Book by Rafay Baloch

=====
Other
=====

This tool is currently maintained by Gianni 'guelfoweb' Amato, who can be contacted at guelfoweb@gmail.com or twitter `@guelfoweb <http://twitter.com/guelfoweb>`_. Suggestions and criticism are welcome.

Sponsored by `Security Side <http://www.securityside.it/>`_
