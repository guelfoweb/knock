import requests
import socket
from . import dns_socket

# socket timeout
timeout = 3
if hasattr(socket, "setdefaulttimeout"): socket.setdefaulttimeout(timeout)

# resolve requests: DNS, HTTP, HTTPS

def dns(target, dns=False):
    try:
        if dns: # use the specified DNS
            return dns_socket._gethostbyname_ex(target, dns)
        return socket.gethostbyname_ex(target)
    except:
        return []

def https(url, useragent):
    headers = {"user-agent": useragent}
    try:
        resp = requests.get("https://"+url, headers=headers, timeout=timeout)
        return [resp.status_code, resp.headers["Server"] if "Server" in resp.headers.keys() else ""]
    except:
        return []

def http(url, useragent):
    headers = {"user-agent": useragent}
    try:
        resp = requests.get("http://"+url, headers=headers, timeout=timeout)
        return [resp.status_code, resp.headers["Server"] if "Server" in resp.headers.keys() else ""]
    except:
        return []