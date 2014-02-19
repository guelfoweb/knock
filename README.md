knock Subdomain Scan
====================

Knock is a python script designed to enumerate subdomains on a target domain through a wordlist.

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

**Other**

This script is currently maintained by Gianni 'guelfoweb' Amato, who can be contacted at guelfoweb@gmail.com. Suggestions and criticism are welcome.
