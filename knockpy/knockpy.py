#!/usr/bin/python3

from argparse import RawTextHelpFormatter
from colorama import Fore, Style
from os import path
import colorama
import argparse
import socket
import requests
import random
import bs4 
import time
import json
import sys
import re
import os
import matplotlib.pyplot as plt
import networkx as nx

try:
    _ROOT = os.path.abspath(os.path.dirname(__file__))
    config_file = os.path.join(_ROOT, "", "config.json")
    config = json.load(open(config_file))
except:
    sys.exit("error in config.json")

if hasattr(socket, "setdefaulttimeout"): socket.setdefaulttimeout(config["timeout"])

class Request():
    def dns(target):
        try:
            return socket.gethostbyname_ex(target)
        except:
            return []

    def https(url):
        headers = {"user-agent": random.choice(config["user_agent"])}
        try:
            resp = requests.get("https://"+url, headers=headers, timeout=config["timeout"])
            return [resp.status_code, resp.headers["Server"] if "Server" in resp.headers.keys() else ""]
        except:
            return []
    def http(url):
        headers = {"user-agent": random.choice(config["user_agent"])}
        try:
            resp = requests.get("http://"+url, headers=headers, timeout=config["timeout"])
            return [resp.status_code, resp.headers["Server"] if "Server" in resp.headers.keys() else ""]
        except:
            return []

    def bs4scrape(params):
        target, url, headers = params
        resp = requests.get(url, headers=headers, timeout=config["timeout"])
        
        pattern = "http(s)?:\/\/(.*)\.%s" % target
        subdomains = []
        if resp.status_code == 200:
            soup = bs4.BeautifulSoup(resp.text, "html.parser")
            for item in soup.find_all("a", href=True):
                if item["href"].startswith("http") and item["href"].find(target) != -1 and item["href"].find("-site:") == -1:
                    match = re.match(pattern, item["href"])
                    if match and re.match("^[a-zA-Z0-9-]*$", match.groups()[1]):
                        subdomains.append(match.groups()[1])
        return list(dict.fromkeys(subdomains))

class Wordlist():
    def local(filename):
        try:
            wlist = open(filename,'r').read().split("\n")
        except:
            _ROOT = os.path.abspath(os.path.dirname(__file__))
            filename = os.path.join(_ROOT, "", filename)
            wlist = open(filename,'r').read().split("\n")
        return filter(None, wlist)
    
    def google(domain):
        headers = {"user-agent": random.choice(config["user_agent"])}
        dork = "site:%s -site:www.%s" % (domain, domain)
        url = "https://google.com/search?q=%s&start=%s" % (dork, str(5))
        params = [domain, url, headers]
        try:
            return Request.bs4scrape(params)
        except Exception as e:
            return []

    def duckduckgo(domain):
        headers = {"user-agent": random.choice(config["user_agent"])}
        dork = "site:%s -site:www.%s" % (domain, domain)
        url = "https://duckduckgo.com/html/?q=%s" % dork
        params = [domain, url, headers]
        try:
            return Request.bs4scrape(params)
        except Exception as e:
            return []

    def virustotal(domain, apikey):
        if not apikey: return []
        url = "https://www.virustotal.com/vtapi/v2/domain/report"
        params = {"apikey": apikey,"domain": domain}
        resp = requests.get(url, params=params)
        resp = resp.json()
        subdomains = [item.replace("."+domain, "") for item in resp["subdomains"]] if "subdomains" in resp.keys() else []
        return subdomains

    def get(domain):
        config_wordlist = config["wordlist"]
    
        config_api = config["api"]
        user_agent = random.choice(config["user_agent"])

        local, google, duckduckgo, virustotal = [], [], [], []

        if "local" in config_wordlist["default"]:
            local = list(Wordlist.local(config_wordlist["local"])) if "local" in config_wordlist["default"] else []

        if "remote" in config_wordlist["default"]:
            google = list(Wordlist.google(domain)) if "google" in config_wordlist["remote"] else []
            duckduckgo = list(Wordlist.duckduckgo(domain)) if "duckduckgo" in config_wordlist["remote"] else []
            virustotal = list(Wordlist.virustotal(domain, config_api["virustotal"])) if "virustotal" in config_wordlist["remote"] else []

        return local, google, duckduckgo, virustotal

class Output():
    def progressPrint(text):
        if not text: text = " "*80
        text_dim = Style.DIM + text + Style.RESET_ALL
        sys.stdout.write("%s\r" % text_dim)
        sys.stdout.flush()
        sys.stdout.write("\r")

    def percentage(i, len_wordlist):
        return (i/len_wordlist)*100

    def colorizeHeader(text, count, sep):
        newText = Style.BRIGHT + Fore.YELLOW + text + Style.RESET_ALL
        _count = str(len(count)) if isinstance(count, list) else str(count)

        newCount = Style.BRIGHT + Fore.CYAN + _count + Style.RESET_ALL

        if len(count) == 0:
            newText = Style.DIM + text + Style.RESET_ALL
            newCount = Style.DIM + _count + Style.RESET_ALL
        newSep = " " + Fore.MAGENTA + sep + Style.RESET_ALL

        return newText + newCount + newSep

    def headerPrint(local, google, duckduckgo, virustotal, domain):
        """
        local: 0 | google: 2 | duckduckgo: 0 | virustotal: 100
        
        Wordlist: 102 | Target: domain.com | Ip: 123.123.123.123
        """

        line = Output.colorizeHeader("local: ", local, "| ")
        line += Output.colorizeHeader("google: ", google, "| ")
        line += Output.colorizeHeader("duckduckgo: ", duckduckgo, "| ")
        line += Output.colorizeHeader("virustotal: ", virustotal, "\n")
        line += "\n"
        line += Output.colorizeHeader("Wordlist: ", local + google + duckduckgo + virustotal, "| ")

        req = Request.dns(domain)
        if req != []:
            ip_req = req[2][0]
            ip = ip_req if req else ""
        else:
            ip = "None"

        line += Output.colorizeHeader("Target: ", domain, "| ")
        line += Output.colorizeHeader("Ip: ", ip, "\n")
        
        return line

    def headerBarPrint(time_start, max_len):
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
        if not "http" in config["attack"]:
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

    def jsonzeRequestData(req, target):
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

    def linePrint(data, max_len):
        """
        123.123.123.123   click.domain.com     click.virt.s6.exactdomain.com
        """ 

        # just a fix, print space if not domain
        _domain = " "*max_len if not data["domain"] else data["domain"]

        if len(data.keys()) == 4:
            spaceIp = " " * (16 - len(data["ipaddr"][0]))
            spaceSub = " " * ((max_len + 1) - len(data["target"]))
            _target = Style.BRIGHT + Fore.CYAN + data["target"] + Style.RESET_ALL if data["alias"] else data["target"]
            line = data["ipaddr"][0] +spaceIp+ _target +spaceSub+ _domain
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

    def footerPrint(time_end, time_start, results):
        """
        21:58:06

        Ip address: 122 | Subdomain: 93 | elapsed time: 00:00:11 
        """

        Output.progressPrint("")
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

        line += Output.colorizeHeader("Ip address: ", list(set(ipList)), "| ")
        line += Output.colorizeHeader("Subdomain: ", list(results.keys()), "| ")
        line += Output.colorizeHeader("elapsed time: ", time.strftime("%H:%M:%S", time.gmtime(elapsed_time)), "\n")

        return line

    def write_json(path, json_data):
        f = open(path, "w")
        f.write(json.dumps(json_data, indent=4))
        f.close()

    def write_csv(path, csv_data):
        f = open(path, "w")
        f.write(csv_data)
        f.close()

class Report():
    def load_json(report):
        try:
            report_json = json.load(open(report))
            del report_json["_meta"]
            return report_json
        except:
            sys.exit("report not found or invalid json")

    def save(results, domain, time_start, time_end, len_wordlist):
        _meta = {
            "name": "knockpy",
            "version": Start.__version__,
            "time_start": time_start,
            "time_end": time_end,
            "domain": domain,
            "wordlist": len_wordlist
            }
        
        results.update({"_meta": _meta})
        folder = config["report"]["folder"]
        strftime = config["report"]["strftime"]
        if not os.path.exists(folder): os.makedirs(folder)
        date = time.strftime(strftime, time.gmtime(time_end)) 
        path = folder + os.sep + domain + "_" + date + ".json"
        Output.write_json(path, results)

    def csv(report):
        csv_data = ""
        for item in report.keys():
            if len(report[item]) == 5:
                """
                https://github.com/guelfoweb/knock/commit/156378d97f10871d30253eeefe15ec399aaa0b03
                https://www.exploit-db.com/exploits/49342
                """
                csv_injection = ("+", "-", "=", "@")
                if report[item]["server"].startswith(csv_injection):
                    report[item]["server"] = "'" + report[item]["server"]
                
                csv_data += "%s;%s;%s;%s;%s" % (report[item]["ipaddr"][0],
                                        report[item]["code"],
                                        item,
                                        report[item]["server"],
                                        report[item]["domain"])
            if len(report[item]) == 3:
                csv_data += "%s;%s;%s" % (report[item]["ipaddr"][0],
                                        item,
                                        report[item]["domain"])
            csv_data += "\n"
        return csv_data

    def terminal(domain):
        report_json = Report.load_json(domain)

        results = ""
        for item in report_json.keys():
            report_json[item].update({"target": item})
            max_len = len(max(list(report_json.keys()), key=len))
            results += Output.linePrint(report_json[item], max_len) + "\n"
        return results

    def plot(report):
        dataset = []
        for item in report.keys():
            dataset.append((report[item]["ipaddr"][0], item))

        g = nx.Graph()
        g.add_edges_from(dataset)

        pos = nx.spring_layout(g)
        nx.draw(g, pos, node_size=50, node_color="r", edge_color="c", with_labels=True, width=0.7, alpha=0.9)
        plt.show()

class Start():
    __version__ = "5.1.0"

    def msg_rnd():
        return ["happy hacking ;)", "good luck!", "never give up!",
                "hacking is not a crime", "https://en.wikipedia.org/wiki/Bug_bounty_program"]

    def parse_and_exit(args):
        if len(args) == 3 and args[1] in ["--report", "--plot", "--csv", "--set"]:

            # report
            if args[1] == "--report":
                if args[2].endswith(".json"):
                    if path.isfile(args[2]):
                        report = Report.terminal(args[2])
                        if report: sys.exit(report)
                    sys.exit("report not found: %s" % args[2])
                sys.exit("use: knockpy --report path/to/domain.com_yyyy_mm_dd_hh_mm_ss.json")

            # plot
            if args[1] == "--plot":
                if args[2].endswith(".json"):
                    if path.isfile(args[2]):
                        report = Report.load_json(args[2])
                        if report: Report.plot(report)
                        sys.exit()
                    sys.exit("report not found: %s" % args[2])
                sys.exit("use: knockpy --plot path/to/domain.com_yyyy_mm_dd_hh_mm_ss.json")

            # csv
            if args[1] == "--csv":
                if args[2].endswith(".json"):
                    if path.isfile(args[2]):
                        report = Report.load_json(args[2])
                        if report: 
                            csv_file = args[2].replace(".json", ".csv")
                            Output.write_csv(csv_file, Report.csv(report))
                            sys.exit("csv report: %s" % csv_file)
                    sys.exit("report not found: %s" % args[2])
                sys.exit("use: knockpy --csv path/to/domain.com_yyyy_mm_dd_hh_mm_ss.json")

            # set
            if args[1] == "--set":
                # virustotal
                if args[2].startswith("apikey-virustotal="):
                    apikey = args[2].split("=")[1]
                    orig_config = json.load(open(config_file))
                    orig_config["api"]["virustotal"] = apikey
                    Output.write_json(config_file, orig_config)
                    sys.exit("%s added!" % apikey)
                
                # timeout
                if args[2].startswith("timeout="):
                    seconds = args[2].split("=")[1]
                    orig_config = json.load(open(config_file))
                    orig_config["timeout"] = int(seconds)
                    Output.write_json(config_file, orig_config)
                    sys.exit("timeout is %s" % seconds)

                sys.exit("use: knockpy --set apikey-virustotal=APIKEY")


    def arguments():
        Start.parse_and_exit(sys.argv)

        description = "-"*80+"\n"
        description += "* SCAN\n"
        description += "full scan:\tknockpy domain.com\n"
        description += "fast scan:\tknockpy domain.com --no-http\n"
        description += "quick scan:\tknockpy domain.com --no-http --no-local\n"
        description += "ignore code:\tknockpy domain.com --no-http-code 404 500 530\n"
        description += "timeout:\tknockpy domain.com -t 2\n\n"
        description += "* REPORT\n"
        description += "show report:\tknockpy --report knockpy_report/domain.com_yyyy_mm_dd_hh_mm_ss.json\n"
        description += "plot report:\tknockpy --plot knockpy_report/domain.com_yyyy_mm_dd_hh_mm_ss.json\n"
        description += "csv report:\tknockpy --csv knockpy_report/domain.com_yyyy_mm_dd_hh_mm_ss.json\n\n"
        description += "* SETTINGS\n"
        description += "set apikey:\tknockpy --set apikey-virustotal=APIKEY\n"
        description += "set timeout:\tknockpy --set timeout=sec\n"
        description += "-"*80
        epilog = "warning:\tapikey virustotal missing (https://www.virustotal.com/)\n\n" if not config["api"]["virustotal"] else "\n\n"
        epilog += "once you get knockpy results, don't forget to use 'nmap' and 'dirsearch'\n\n"
        epilog += random.choice(Start.msg_rnd())

        parser = argparse.ArgumentParser(prog="knockpy", description=description, epilog=epilog, formatter_class=RawTextHelpFormatter)
        parser.add_argument("domain", help="target to scan")
        parser.add_argument("-v", "--version", action="version", version="%(prog)s " + Start.__version__)
        parser.add_argument("--no-local", help="local wordlist ignore", action="store_true", required=False)
        parser.add_argument("--no-remote", help="remote wordlist ignore", action="store_true", required=False)
        parser.add_argument("--no-http", help="http requests ignore\n\n", action="store_true", required=False)
        parser.add_argument("--no-http-code", help="http code list to ignore\n\n", nargs="+", dest="code", type=int, required=False)
        parser.add_argument("-w", help="wordlist file to import", dest="wordlist", required=False)
        parser.add_argument("-o", help="report folder to store json results", dest="folder", required=False)
        parser.add_argument("-t", help="timeout in seconds", nargs=1, dest="sec", type=int, required=False)

        args = parser.parse_args()

        domain = args.domain

        if domain.startswith("http"): sys.exit("remove protocol http(s)://")
        if domain.startswith("www."): sys.exit("remove www.")
        if domain.find(".") == -1: sys.exit("invalid domain")

        if args.no_local and args.no_remote: sys.exit("no wordlist")
        if args.no_local:
            if "local" in config["wordlist"]["default"]:
                config["wordlist"]["default"].remove("local") 
        if args.no_remote:
            if "local" in config["wordlist"]["default"]:
                config["wordlist"]["default"].remove("remote")

        if args.no_http:
            if "http" in config["attack"]:
                config["attack"].remove("http")
        
        if args.code:
            config["no_http_code"] = args.code

        if args.folder:
            if not os.access(args.folder, os.W_OK): sys.exit("folder not writable: " + args.folder)
            config["report"]["folder"] = args.folder
            config["report"]["save"] = True

        if args.sec:
            config["timeout"] = args.sec[0]

        if args.wordlist:
            config["wordlist"]["local"] = args.wordlist

        return domain



    def logo():
        return """
  _  __                 _                
 | |/ /                | |   v%s            
 | ' / _ __   ___   ___| | ___ __  _   _ 
 |  < | '_ \ / _ \ / __| |/ / '_ \| | | |
 | . \| | | | (_) | (__|   <| |_) | |_| |
 |_|\_\_| |_|\___/ \___|_|\_\ .__/ \__, |
                            | |     __/ |
                            |_|    |___/ 
""" % Start.__version__
    


def main():
    domain = Start.arguments()
    
    # action: scan
    print (Start.logo())

    # wordlist
    Output.progressPrint("getting wordlist ...")
    local, google, duckduckgo, virustotal = Wordlist.get(domain)
    wordlist = list(dict.fromkeys((local + google + duckduckgo + virustotal)))
    wordlist = sorted(wordlist, key=str.lower)
    max_len = len(max(wordlist, key=len) + "." + domain) if wordlist else sys.exit("\nno wordlist")

    if not wordlist: sys.exit("no wordlist")

    # header
    print (Output.headerPrint(local, google, duckduckgo, virustotal, domain))
    time_start = time.time()
    print (Output.headerBarPrint(time_start, max_len))

    # init
    i = 0
    len_wordlist = len(wordlist)
    results = {}
    
    # start
    for subdomain in wordlist:
        i = i+1
        percentage = str(int(Output.percentage(i, len_wordlist)))+"% (ctrl-z) | "

        Output.progressPrint(percentage + subdomain)
        target = subdomain+"."+domain

        Output.progressPrint(percentage + "DNS -> %s" % target+" "*max_len)
        req = Request.dns(target)

        if not req: continue

        req = list(req)
        ip_req = req[2][0]

        if ip_req in config["ignore"]: continue

        # dns only
        if not "http" in config["attack"]:
            # print line and update report
            data = Output.jsonzeRequestData(req, target)
            print (Output.linePrint(data, max_len))
            del data["target"]
            results.update({target: data})
            continue

        # dns and http(s)
        Output.progressPrint(percentage + "dns: %s | https://%s" % (ip_req, target))
        https = Request.https(target)
        
        if https:
            for item in https:
                req.append(item)
        else:
            Output.progressPrint(percentage + "dns: %s | https: no | http://%s" % (ip_req, target))
            http = Request.http(target)
            
            if http:
                for item in http:
                    req.append(item)
            else:
                req.append("")
                req.append("")

        # print line and update report
        data = Output.jsonzeRequestData(req, target)
        if data["code"] in config["no_http_code"]: continue
        print (Output.linePrint(data, max_len))
        del data["target"]
        results.update({target: data})

    # footer
    time_end = time.time()
    print (Output.footerPrint(time_end, time_start, results))

    # save report
    if config["report"]["save"]: Report.save(results, domain, time_start, time_end, len_wordlist)

if __name__ == "__main__":
    main()
