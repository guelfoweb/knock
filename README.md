knock Subdomain Scan
====================

Knock is a python tool designed to enumerate subdomains on a target domain through a wordlist.

**Usage**

<code>$ knock.py domain.com</code>

<code>$ knock.py domain.com **--worlist** wordlist.txt</code>

**Options**

<pre>
	-h, --help      This help
	-v, --version   Show version
	    --wordlist  Use personal wordlist
</pre>

**Options for single domain**

<pre>
	-i, --info      Short information
	-r, --resolve   Resolve domain name
	-w, --wilcard   Check if wildcard is enabled
	-z, --zone      Check if Zonte Transfer is enabled
</pre>

<code>$ knock.py **[-opt, --option]** domain.com</code>

**Note**

<pre>
The ALIAS name is marked in yellow.
</pre>

Install
=======
**Prerequisites**

<code>Python 2.6.5 or 2.7</code>

**Download**

<code>git clone https://github.com/guelfoweb/knock.git</code>

**Other**

This script is currently maintained by Gianni 'guelfoweb' Amato, who can be contacted at guelfoweb@gmail.com. Suggestions and criticism are welcome.
