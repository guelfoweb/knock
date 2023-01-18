from colorama import Fore, Style
from . import request
import time
import json
import sys

# print progressbar
def progressPrint(text):
    if not text: text = " "*80
    text_dim = Style.DIM + text + Style.RESET_ALL
    sys.stdout.write("%s\r" % text_dim)
    sys.stdout.flush()
    sys.stdout.write("\r")

# colorize line
def colorizeHeader(text, count, sep):
    newText = Style.BRIGHT + Fore.YELLOW + text + Style.RESET_ALL
    _count = str(len(count)) if isinstance(count, list) else str(count)

    newCount = Style.BRIGHT + Fore.CYAN + _count + Style.RESET_ALL

    if len(count) == 0:
        newText = Style.DIM + text + Style.RESET_ALL
        newCount = Style.DIM + _count + Style.RESET_ALL
    newSep = " " + Fore.MAGENTA + sep + Style.RESET_ALL

    return newText + newCount + newSep

# print wordlist and target information
def headerPrint(local, remote, domain):
    """
    local: 0 | remote: 270
    
    Wordlist: 270 | Target: domain.com | Ip: 123.123.123.123
    """

    line = colorizeHeader("local: ", local, "| ")
    line += colorizeHeader("remote: ", remote, "\n")
    line += "\n"
    line += colorizeHeader("Wordlist: ", local + remote, "| ")

    req = request.dns(domain)
    if req != []:
        ip_req = req[2][0]
        ip = ip_req if req else ""
    else:
        ip = "None"

    line += colorizeHeader("Target: ", domain, "| ")
    line += colorizeHeader("Ip: ", ip, "\n")
    
    return line

# print header before of match-line (linePrint)
def headerBarPrint(time_start, max_len, no_http):
    """
    21:57:55

    Ip address      Subdomain               Real hostname
    --------------- ----------------------- ----------------------------
    """

    # time_start
    line = Style.BRIGHT
    line += time.strftime("%H:%M:%S", time.gmtime(time_start)) + "\n\n"

    # spaces
    spaceIp = " " * (16 - len("Ip address"))
    spaceSub = " " * ((max_len + 1) - len("Subdomain"))

    # dns only
    if no_http:
        line += "Ip address" +spaceIp+ "Subdomain" +spaceSub+ "Real hostname" + "\n"
        line += Style.RESET_ALL
        line += "-" * 15 + " " + "-" * max_len + " " + "-" * max_len
    
    # http
    else:
        spaceCode = " " * (5 - len("Code"))
        spaceServ = " " * ((max_len + 1) - len("Server"))
        line += "Ip address" +spaceIp+ "Code" +spaceCode+ "Subdomain" +spaceSub+ "Server" +spaceServ+ "Real hostname" + "\n"
        line += Style.RESET_ALL
        line += "-" * 15 + " " + "-" * 4 + " " + "-" * max_len + " " + "-" * max_len + " " + "-" * max_len
    
    return line

# change json for different scan: dns or dns + http
def jsonizeRequestData(req, target):
    if len(req) == 3:
        subdomain, aliasList, ipList = req
        domain = subdomain if subdomain != target else ""

        data = {
            "target": target,
            "domain": domain,
            "alias": aliasList,
            "ipaddr": ipList
            }
    elif len(req) == 5:
        subdomain, aliasList, ipList, code, server = req
        domain = subdomain if subdomain != target else ""

        data = {
            "target": target,
            "domain": domain,
            "alias": aliasList,
            "ipaddr": ipList,
            "code": code,
            "server": server
            }
    else:
        data = {}

    return data

# print match-line while it's working
def linePrint(data, max_len):
    """
    123.123.123.123   click.domain.com     click.virt.s6.exactdomain.com
    """ 

    # just a fix, print space if not domain
    _domain = " "*max_len if not data["domain"] else data["domain"]

    # case dns only
    if len(data.keys()) == 4:
        spaceIp = " " * (16 - len(data["ipaddr"][0]))
        spaceSub = " " * ((max_len + 1) - len(data["target"]))
        _target = Style.BRIGHT + Fore.CYAN + data["target"] + Style.RESET_ALL if data["alias"] else data["target"]
        line = data["ipaddr"][0] +spaceIp+ _target +spaceSub+ _domain
    
    # case dns +http
    elif len(data.keys()) == 6:
        data["server"] = data["server"][:max_len]

        spaceIp = " " * (16 - len(data["ipaddr"][0]))
        spaceSub = " " * ((max_len + 1) - len(data["target"]))
        spaceCode = " " * (5 - len(str(data["code"])))
        spaceServer = " " * ((max_len + 1) - len(data["server"]))
        
        if data["code"] == 200:
            _code = Style.BRIGHT + Fore.GREEN + str(data["code"]) + Style.RESET_ALL
            _target = Style.BRIGHT + Fore.GREEN + data["target"] + Style.RESET_ALL
        elif str(data["code"]).startswith("4"):
            _code = Style.BRIGHT + Fore.MAGENTA + str(data["code"]) + Style.RESET_ALL
            _target = Style.BRIGHT + Fore.MAGENTA + data["target"] + Style.RESET_ALL
        elif str(data["code"]).startswith("5"):
            _code = Style.BRIGHT + Fore.RED + str(data["code"]) + Style.RESET_ALL
            _target = Style.BRIGHT + Fore.RED + data["target"] + Style.RESET_ALL
        else:
            _code = str(data["code"])
            _target = Style.BRIGHT + Fore.CYAN + data["target"] + Style.RESET_ALL if data["domain"] else data["target"]

        line = data["ipaddr"][0] +spaceIp+ _code +spaceCode+ _target +spaceSub+ data["server"] +spaceServer+ _domain

    return line

# print footer at the end after match-line (linePrint)
def footerPrint(time_end, time_start, results):
    """
    21:58:06

    Ip address: 122 | Subdomain: 93 | elapsed time: 00:00:11 
    """

    progressPrint("")
    elapsed_time = time_end - time_start
    line = Style.BRIGHT
    line += "\n"
    line += time.strftime("%H:%M:%S", time.gmtime(time_end))
    line += "\n\n"
    line += Style.RESET_ALL

    ipList = []
    for i in results.keys():
        for ii in results[i]["ipaddr"]:
            ipList.append(ii)

    line += colorizeHeader("Ip address: ", list(set(ipList)), "| ")
    line += colorizeHeader("Subdomain: ", list(results.keys()), "| ")
    line += colorizeHeader("elapsed time: ", time.strftime("%H:%M:%S", time.gmtime(elapsed_time)), "\n")

    return line

# create json file
def write_json(path, json_data):
    f = open(path, "w")
    f.write(json.dumps(json_data, indent=4))
    f.close()

# create csv file
def write_csv(path, csv_data):
    f = open(path, "w")
    f.write(csv_data)
    f.close()