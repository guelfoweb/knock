#!/usr/bin/env python

# ----------------------------------------------------------------------
# This file is part of Knock Subdomain Scan.
#
# Knock is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Knock is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Knock. If not, see <http://www.gnu.org/licenses/>.
# ----------------------------------------------------------------------

import sys
import socket
import string
import random
# backward compatibility with python2
if sys.version[0] == "2":
    import httplib
else:
    import http.client


# set the default timeout on sockets to 5 seconds
if hasattr(socket, 'setdefaulttimeout'):
    socket.setdefaulttimeout(5)  # <- here


def domaininfo(domain):
    try:
        # translate a host name to IPv4 address format
        host = socket.gethostbyname(domain)
    except:
        pass
        return False

    if host:
        # return a triple (hostname, aliaslist, ipaddrlist) by HOST
        soc = socket.gethostbyname_ex(domain)
        # print(soc) # enable for debug
        elem = []
        hostname = soc[0]
        ip = soc[2][0]

        elem.append([hostname])

        # verbose
        len_alias_array = len(soc[1])
        if len_alias_array > 0:
            for i in range(0, len_alias_array):
                alias = soc[1][i]
                try:
                    # Return a triple (hostname, aliaslist, ipaddrlist) by IP
                    name = socket.gethostbyaddr(soc[1][i])[0]
                    ip = socket.gethostbyname(name)
                except:
                    name = alias
                    ip = socket.gethostbyname(alias)
                    pass

                elem.append([alias, name, ip])
        else:
            elem.append([ip])

        return (elem)
        soc.close()


def zonetransfer(URL):  # Zone Transfer
    try:
        import dns.query, dns.zone, dns.resolver

        answers = dns.resolver.query(URL, 'NS')
        ns = []
        for rdata in answers:
            n = str(rdata)
            ns_array = domaininfo(n)
            print(str(ns_array[1][0]) + "\t" + str(ns_array[0][0]))
            ns.append(n)

        print()

        for n in ns:
            zt = []
            try:
                zone = dns.zone.from_xfr(dns.query.xfr(ns[0], URL))
                for name, node in zone.nodes.items():
                    rdataset = node.rdatasets
                    for record in rdataset:
                        if not str(name) == "@" and not str(name) == "*":
                            zt.append(str(name) + "." + URL)
                return zt
                # print, "\n%s\t%s" % (name, record)
                #break
                print()
            except:
                return False
                pass
    except:
        return False


def loadfile(filename):
    try:
        filename = open(filename, 'r')
        wlist = filename.read().split('\n')
        filename.close
        return wlist
    except:
        return False


def rnd():  # random string
    alphabet = 'abcdefghijklmnopqrstuvwxyz'
    min = 5
    max = 15
    total = 2
    rndstring = ''
    for count in xrange(1, total):
        for x in random.sample(alphabet, random.randint(min, max)):
            rndstring += x
    return rndstring


def testwildcard(url):
    rndString = rnd()  # get random string
    subdomain = rndString + "." + url
    try:
        host = socket.gethostbyname(subdomain)
        return True
    except:
        return False


agent = "Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_6; en-US) AppleWebKit/534.10 (KHTML, like Gecko) Chrome/8.0.552.237 Safari/534.10"


def getheader(url, path, method):
    try:
        conn = httplib.HTTPConnection(url)
        conn.putrequest(method, path)
        conn.putheader("User-Agent", agent)
        # Test for XST
        # conn.putheader("Via", "<script>alert(0)</script>")
        conn.endheaders()
        #		conn.request(method, path)
        res = conn.getresponse()
        return res.status, res.reason, res.getheaders()
        conn.close()
    except:
        return False

# for debug
# print(zonetransfer("zonetransfer.me"))
#print(getheader("egfrgfwr.reddit.com"))
#subscan("google.com", "wordlist.txt")
