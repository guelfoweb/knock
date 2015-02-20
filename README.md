knock Subdomain Scan v.3.0
====================

Knock is a python tool designed to enumerate subdomains on a target domain through a wordlist.

**Usage**

<code>$ knock.py domain.com</code>

<code>$ knock.py domain.com **--wordlist** wordlist.txt</code>

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

<code>Python 2.6.5 -> 2.7.x</code>

**Download**

<code>$ git clone https://github.com/guelfoweb/knock.git</code>

or <b><a href="https://github.com/guelfoweb/knock/archive/master.zip" alt="knock-master.zip" title="knock-master.zip">Download Zip</a></b> and extract <code>knock</code> folder.

**Note**

Is recommended to use <a href="https://developers.google.com/speed/public-dns/docs/using">Google DNS</a> <code>8.8.8.8</code> | <code>8.8.4.4</code>

Example
=======

<code>$ python knock.py yahoo.com</code>

<pre>
Getting NS records for yahoo.com
 
Ip Address      Server Name
----------      -----------
202.43.223.170  ns6.yahoo.com
68.142.255.16   ns2.yahoo.com
202.165.104.22  ns8.yahoo.com
203.84.221.53   ns3.yahoo.com
68.180.131.16   ns1.yahoo.com
119.160.247.124 ns5.yahoo.com
98.138.11.157   ns4.yahoo.com
 
Getting subdomain for yahoo.com
 
Ip Address      Domain Name
----------      -----------
68.180.194.127  9.yahoo.com
68.180.194.127  studios1.fy9.b.yahoo.com
216.145.48.74   adkit.yahoo.com
216.145.48.74   public.yahoo.com
98.138.253.136  admin.yahoo.com
98.138.253.136  admin.my.lga1.b.yahoo.com
217.163.21.39   ads.yahoo.com

- - - <a href="http://pastebin.com/FrHEkHAs">Full output on pastebin</a> - - -

77.238.160.51   za.yahoo.com
77.238.160.51   ir2.fp.vip.ch1.yahoo.com
46.228.47.115   fd-fp2.wg1.b.yahoo.com
46.228.47.115   ir1.fp.vip.ir2.yahoo.com
46.228.47.114   ds-fp2.wg1.b.yahoo.com
46.228.47.114   ir2.fp.vip.ir2.yahoo.com
77.238.160.51   ds-any-fp2.wa1.b.yahoo.com
46.228.47.115   ds-any-fp2.wa1.b.yahoo.com
46.228.47.114   ds-any-fp2.wa1.b.yahoo.com
 
Ip Addr Summary
---------------
68.180.194.127
216.145.48.74
98.138.253.136
217.163.21.39
217.163.21.35
217.163.21.36

- <a href="http://pastebin.com/FrHEkHAs">Full output</a> -

66.218.72.112
216.145.54.174
206.190.37.187
68.180.147.88
66.228.160.206
216.252.113.12
66.218.85.160
 
Found 415 subdomain(s) in 88 host(s).
</pre>

Credit
======

Thanks to Bob Halley for <code>dnspython</code> toolkit

**Talk about...**
<ul>
<li><a href="http://www.amazon.com/Ethical-Hacking-Penetration-Testing-Guide/dp/1482231611">Ethical Hacking and Penetration Testing Guide</a> <i>Book by Rafay Baloch</i></li>
</ul>

Other
=====

This tool is currently maintained by Gianni 'guelfoweb' Amato, who can be contacted at guelfoweb@gmail.com or twitter <a href="http://twitter.com/guelfoweb">@guelfoweb</a>. Suggestions and criticism are welcome.

Sponsored by **<a href="http://www.securityside.it/">Security Side</a>**.
