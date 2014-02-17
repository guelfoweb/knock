knock Subdomain Scan
====================

Knock is a python script designed to enumerate subdomains on a target domain through a wordlist.

**Usage**

<pre>
$ knock.py domain.com
$ knock.py domain.com --worlist wordlist.txt
</pre>

**Options**

<pre>
	-h, --help	This help
	-v, --version	Show version
	    --wordlist	Use personal wordlist
</pre>

**Options for single domain**

<pre>
	-i, --info	Short information
	-r, --resolve	Resolve domain name
	-w, --wilcard	Check if wildcard is enabled
	-z, --zone	Check if Zonte Transfer is enabled
	    --get	Request HTTP for GET method
	    --post	Request HTTP for POST method
	    --head	Request HTTP for HEAD method
	    --trace	Request HTTP for TRACE method
	    --options	Request HTTP for OPTIONS method
</pre>

**Note**

<pre>
The ALIAS name is marked in yellow.
</pre>
