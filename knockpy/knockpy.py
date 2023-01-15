#!/usr/bin/python3
# -*- coding: utf-8 -*-

from importlib.machinery import SourceFileLoader
from argparse import RawTextHelpFormatter
from colorama import Fore, Style
import concurrent.futures
import colorama
import argparse
import socket
from knockpy.lib import dns_socket
import requests
import random
import time
import json
import sys
import re
import os

# socket timeout
timeout = 3
if hasattr(socket, "setdefaulttimeout"): socket.setdefaulttimeout(timeout)

user_agent = [
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.14; rv:65.0) Gecko/20100101 Firefox/65.0",
    "Mozilla/5.0 (MSIE 10.0; Windows NT 6.1; Trident/5.0)",
    "Opera/9.80 (Windows NT 6.0) Presto/2.12.388 Version/12.14",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_3) AppleWebKit/537.75.14 (KHTML, like Gecko) Version/7.0.3 Safari/7046A194A"
]

_ROOT = os.path.abspath(os.path.dirname(__file__))

# resolve requests: DNS, HTTP, HTTPS
class Request():
    def dns(target):
        try:
            if dns: # use the specified DNS
                return dns_socket._gethostbyname_ex(target, dns)
            return socket.gethostbyname_ex(target)
        except:
            return []

    def https(url):
        headers = {"user-agent": useragent}
        try:
            resp = requests.get("https://"+url, headers=headers, timeout=timeout)
            return [resp.status_code, resp.headers["Server"] if "Server" in resp.headers.keys() else ""]
        except:
            return []
    
    def http(url):
        headers = {"user-agent": useragent}
        try:
            resp = requests.get("http://"+url, headers=headers, timeout=timeout)
            return [resp.status_code, resp.headers["Server"] if "Server" in resp.headers.keys() else ""]
        except:
            return []

# get and purge local/remote wordlist
class Wordlist():
    # get local dictionary
    def local(filename):
        try:
            filename = os.path.join(_ROOT, "", filename)
            wlist = open(filename,'r').read().split("\n")
        except:
            if not silent_mode: Output.progressPrint("wordlist not found: {filename}".format(filename=filename))
            return []
            #sys.exit("wordlist not found: {filename}".format(filename=filename))
        return filter(None, wlist)
    
    # get remote wordlist using plugin
    def remotescan(domain):
        result = []

        # plugin directory
        dir_plugins = _ROOT + '{sep}remote'.format(sep=os.sep)
        
        for (dir_plugins, dir_names, plugins) in os.walk(dir_plugins):
            for plugin in plugins:

                # filter for .py scripts and exclude __init__.py file
                if plugin.endswith('.py') and plugin != '__init__.py':
                    plugin_path = os.path.join(dir_plugins, plugin)
                    
                    try:
                        # load module
                        foo = SourceFileLoader(plugin, plugin_path).load_module()
                        if not silent_mode: 
                            Output.progressPrint('') # print empty line
                            Output.progressPrint(plugin) # print name of the module
                        
                        # get module's result
                        plugin_result = foo.get(domain)
                        
                        # add subdomains
                        result = result + plugin_result
                    except:
                        # print plugin error and sleep 3 secs.
                        if not silent_mode: 
                            Output.progressPrint("error plugin -> "+plugin)
                            time.sleep(3)
                        continue
        
        result = list(set([r.lower() for r in result]))
        subdomains = [item.replace('.'+domain, '') for item in result]
        return subdomains

    # purge wordlist
    def purge(wordlist):
        return [word for word in wordlist if word and re.match("[a-z0-9\.-]", word)]

    # get wordlist local and/or remote
    def get(domain):
        local, remote = [], []

        if not no_local:
            local = list(Wordlist.local(local_wordlist))

        if not no_remote:
            remote = list(Wordlist.remotescan(domain))

        return local, remote

# manage terminal output
class Output():
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

        line = Output.colorizeHeader("local: ", local, "| ")
        line += Output.colorizeHeader("remote: ", remote, "\n")
        line += "\n"
        line += Output.colorizeHeader("Wordlist: ", local + remote, "| ")

        req = Request.dns(domain)
        if req != []:
            ip_req = req[2][0]
            ip = ip_req if req else ""
        else:
            ip = "None"

        line += Output.colorizeHeader("Target: ", domain, "| ")
        line += Output.colorizeHeader("Ip: ", ip, "\n")
        
        return line

    # print header before of match-line (linePrint)
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

class Report():
    # import json file
    def load_json(report):
        try:
            report_json = json.load(open(report))
            del report_json["_meta"]
            return report_json
        except:
            sys.exit("report not found or invalid json")

    # save output and add _meta to json file
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
        strftime = "%Y_%m_%d_%H_%M_%S"
        date = time.strftime(strftime, time.gmtime(time_end)) 
        path = output_folder + os.sep + domain + "_" + date + ".json"
        Output.write_json(path, results)

    # convert json to csv
    def csv(report):
        csv_data = ""
        for item in report.keys():
            if len(report[item]) == 5:
                """
                fix injection:
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

    # convert json to human text to show in terminal
    def terminal(domain):
        report_json = Report.load_json(domain)

        results = ""
        for item in report_json.keys():
            report_json[item].update({"target": item})
            max_len = len(max(list(report_json.keys()), key=len))
            results += Output.linePrint(report_json[item], max_len) + "\n"
        return results

    # plotting relationships
    def plot(report):
        # todo:
        # get modules list from sys.modules.keys()
        try:
            import matplotlib.pyplot as plt
            import networkx as nx
        except:
            print("Plot needs these libraries. Use 'pip' to install them:\n- matplotlib\n- networkx\n- PyQt5")
            sys.exit(1)

        dataset = []
        for item in report.keys():
            dataset.append((report[item]["ipaddr"][0], item))

        g = nx.Graph()
        g.add_edges_from(dataset)

        pos = nx.spring_layout(g)
        nx.draw(g, pos, node_size=50, node_color="r", edge_color="c", with_labels=True, width=0.7, alpha=0.9)
        plt.show()

class Start():
    __version__ = "6.0.0"

    # print random message
    def msg_rnd():
        return ["happy hacking ;)", "good luck!", "never give up!",
                "hacking is not a crime", "https://en.wikipedia.org/wiki/Bug_bounty_program"]

    # check for valid domain
    # it's used in Start.arguments() and Scanning.start()
    def is_valid_domain(domain):
        if not isinstance(domain, str) or not re.match("[a-z0-9\.-]", domain) or domain.startswith(("http", "www.")):
            return False
        return True

    # when domain not is a domain name but it's a command
    def parse_and_exit(args):
        if len(args) == 3 and args[1] in ["--report", "--plot", "--csv", "--set"]:

            # report
            if args[1] == "--report":
                if args[2].endswith(".json"):
                    if os.path.isfile(args[2]):
                        report = Report.terminal(args[2])
                        if report: sys.exit(report)
                    sys.exit("report not found: %s" % args[2])
                sys.exit("try using: knockpy --report path/to/domain.com_yyyy_mm_dd_hh_mm_ss.json")

            # plot
            if args[1] == "--plot":
                if args[2].endswith(".json"):
                    if os.path.isfile(args[2]):
                        report = Report.load_json(args[2])
                        if report: Report.plot(report)
                        sys.exit()
                    sys.exit("report not found: %s" % args[2])
                sys.exit("try using: knockpy --plot path/to/domain.com_yyyy_mm_dd_hh_mm_ss.json")

            # csv
            if args[1] == "--csv":
                if args[2].endswith(".json"):
                    if os.path.isfile(args[2]):
                        report = Report.load_json(args[2])
                        if report: 
                            csv_file = args[2].replace(".json", ".csv")
                            Output.write_csv(csv_file, Report.csv(report))
                            sys.exit("csv report: %s" % csv_file)
                    sys.exit("report not found: %s" % args[2])
                sys.exit("try using: knockpy --csv path/to/domain.com_yyyy_mm_dd_hh_mm_ss.json")

    def arguments():
        # check if domain string is a command
        Start.parse_and_exit(sys.argv)

        description = "-"*80+"\n"
        description += "* SCAN\n"
        description += "full scan:\tknockpy domain.com\n"
        description += "quick scan:\tknockpy domain.com --no-local\n"
        description += "faster scan:\tknockpy domain.com --no-local --no-http\n"
        description += "ignore code:\tknockpy domain.com --no-http-code 404 500 530\n"
        description += "silent mode:\tknockpy domain.com --silent\n\n"
        description += "* SUBDOMAINS\n"
        description += "show recon:\tknockpy domain.com --no-local --no-scan\n\n"
        description += "* REPORT\n"
        description += "show report:\tknockpy --report knockpy_report/domain.com_yyyy_mm_dd_hh_mm_ss.json\n"
        description += "plot report:\tknockpy --plot knockpy_report/domain.com_yyyy_mm_dd_hh_mm_ss.json\n"
        description += "csv report:\tknockpy --csv knockpy_report/domain.com_yyyy_mm_dd_hh_mm_ss.json\n"
        description += "-"*80
        
        epilog = "once you get knockpy results, don't forget to use 'nmap' and 'dirsearch'\n\n"
        epilog += random.choice(Start.msg_rnd())

        parser = argparse.ArgumentParser(prog="knockpy", description=description, epilog=epilog, 
            formatter_class=RawTextHelpFormatter)

        parser.add_argument("domain", nargs='?', help="target to scan", default=sys.stdin, type=str)
        parser.add_argument("-v", "--version", action="version", version="%(prog)s " + Start.__version__)
        parser.add_argument("--no-local", help="local wordlist ignore", action="store_true", required=False)
        parser.add_argument("--no-remote", help="remote wordlist ignore", action="store_true", required=False)
        parser.add_argument("--no-scan", help="scanning ignore, show wordlist and exit", action="store_true", required=False)
        parser.add_argument("--no-http", help="http requests ignore\n\n", action="store_true", required=False)
        parser.add_argument("--no-http-code", help="http code list to ignore\n\n", nargs="+", dest="code", type=int, required=False)
        parser.add_argument("--no-ip", help="ip address to ignore\n\n", nargs="+", type=str, required=False)
        parser.add_argument("--dns", help="use custom DNS ex. 8.8.8.8\n\n", dest="dns", required=False)
        parser.add_argument("--user-agent", help="use a custom user agent\n\n", dest="useragent", required=False)

        parser.add_argument("-w", help="wordlist file to import", dest="wordlist", required=False)
        parser.add_argument("-o", help="report folder to store json results", dest="folder", required=False)
        parser.add_argument("-t", help="timeout in seconds", dest="sec", type=int, required=False)
        parser.add_argument("-th", help="threads num\n\n", dest="num", type=int, required=False)

        parser.add_argument("--silent", 
            default=False,
            nargs="?",
            choices=[False, "json", "json-pretty", "csv"],
            help="silent or quiet mode, default output: False\n\n", 
            )

        args = parser.parse_args()

        # --no-ip ignore ip addresses
        global no_ip
        no_ip = args.no_ip if args.no_ip else ["127.0.0.1"]

        # --no-scan ignore scanning
        global no_scan
        no_scan = args.no_scan

        # --silent set silent mode
        """
        silent_mode is False by default.
        --silent without args -> the value is None, then I change it in "no-output"
        --silent with args -> it keep argument passed, ex: --silent csv
        """
        global silent_mode
        silent_mode = args.silent 
        if silent_mode == None:
            silent_mode = "no-output"

        # get domain name via positional argument or stdin
        if sys.stdin.isatty():
            # positional
            # knockpy domain.com
            domain = args.domain
        else:
            # stdin
            # echo "domain.com" | knockpy
            domain = args.domain.read()

        # check if the domain name is correct
        if not Start.is_valid_domain(domain):
            parser.print_help(sys.stderr)
            sys.exit()

        # choice wordlist
        if args.no_local and args.no_remote: sys.exit("no wordlist")

        # --no-local exclude local dictionary
        global no_local
        no_local = True if args.no_local else False
        
        # --no-remote exclude remote dictionary
        global no_remote
        no_remote = True if args.no_remote else False

        # --no-http ignore requests
        global no_http
        no_http = True if args.no_http else False

        
        # --no-http-code ignore http code
        global no_http_code
        no_http_code = args.code if args.code else []

        # -o set report folder
        global output_folder
        output_folder = args.folder if args.folder else "knockpy_report"

        # check that the "-o false" parameter was not supplied
        if output_folder != "false":
            # create folder if not exists
            if not os.path.exists(output_folder): os.makedirs(output_folder)
            # check if the folder is accessible
            if not os.access(output_folder, os.W_OK): sys.exit("folder not exists or not writable: " + output_folder)
        
        # save output depends on the -o option
        # it's True by default except when "-o false"
        global save_output
        save_output = False if output_folder.lower() == "false" else True

        # -t set timeout default is 3
        global timeout
        timeout = args.sec if args.sec else 3

        # -th set threads default is 30
        global threads
        threads = args.num if args.num else 30

        # -w set path to local wordlist default is "wordlist.txt"
        global local_wordlist
        local_wordlist = args.wordlist if args.wordlist else _ROOT + "{sep}local{sep}wordlist.txt".format(sep=os.sep)

        # --dns set dns default is False
        global dns
        dns = args.dns if args.dns else False

        # --user-agent
        global useragent
        useragent = args.useragent if args.useragent else random.choice(user_agent)

        return domain


    def scan(max_len, domain, subdomain, percentage, results):
        ctrl_c = "(ctrl+c) | "

        #Output.progressPrint(ctrl_c + subdomain)
        target = subdomain+"."+domain
        if not silent_mode: Output.progressPrint(ctrl_c + str(percentage*100)[:4] + "% | " + target + " "*max_len)
        req = Request.dns(target)

        if not req: return None

        req = list(req)
        ip_req = req[2][0]

        if ip_req in no_ip: return None

        # dns only
        if no_http:
            # print line and update report
            data = Output.jsonizeRequestData(req, target)
            if not silent_mode: print (Output.linePrint(data, max_len))
            del data["target"]
            return results.update({target: data})

        # dns and http(s)
        https = Request.https(target)
        
        if https:
            for item in https:
                req.append(item)
        else:
            http = Request.http(target)
            
            if http:
                for item in http:
                    req.append(item)
            else:
                req.append("")
                req.append("")

        # print line and update report
        data = Output.jsonizeRequestData(req, target)
        if data["code"] in no_http_code: return None
        if not silent_mode: print (Output.linePrint(data, max_len))
        del data["target"]
        return results.update({target: data})


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

class Scanning:
    """
    # module to import in python script:

    from knockpy import knockpy

    # return json results
    results = knockpy.Scanning.start("domain.com", params)
    """
    
    def start(domain, params=False):
        # default params
        params_default = {
            "no_local": False,  # [bool] local wordlist ignore
            "no_remote": False, # [bool] remote wordlist ignore
            "no_scan": False,   # [bool] scanning ignore, show wordlist
            "no_http": False,   # [bool] http requests ignore
            "no_http_code": [], # [list] http code list to ignore
            "no_ip": [],        # [list] ip address to ignore
            "dns": "",          # [str] use custom DNS ex. 8.8.8.8
            "timeout": 3,       # [int] timeout in seconds
            "threads": 30,      # [int] threads num
            "useragent": "",    # [str] use a custom user agent
            "wordlist": ""      # [str] path to custom wordlist
        }

        # params validation
        if not params:
            params = params_default
        else:
            for param in params_default.keys():
                value = params_default[param]
                if param not in params:
                    params.update({param: value})

        # domain validation
        if not Start.is_valid_domain(domain):
            return False

        # global flags by params
        global no_local
        no_local = params["no_local"]
        global no_remote
        no_remote = params["no_remote"]

        if no_local and no_remote: # case no wordlist
            return None

        global no_scan
        no_scan = params["no_scan"]
        global no_http
        no_http = params["no_http"]
        global no_http_code
        no_http_code = params["no_http_code"]
        global no_ip
        no_ip = params["no_ip"]
        global dns
        dns = params["dns"] if params["dns"] else False
        global timeout
        timeout = params["timeout"]
        global threads
        threads = params["threads"]
        global useragent
        useragent = params["useragent"] if params["useragent"] else random.choice(user_agent)
        global local_wordlist
        local_wordlist = params["wordlist"] if params["wordlist"] else _ROOT + "{sep}local{sep}wordlist.txt".format(sep=os.sep)
        
        # global flags by default
        global silent_mode
        silent_mode = "json"
        global output_folder
        output_folder = False

        # get wordlist
        local, remote = Wordlist.get(domain)
        local = Wordlist.purge(local)
        remote = Wordlist.purge(remote)
        wordlist = list(dict.fromkeys((local + remote)))
        wordlist = sorted(wordlist, key=str.lower)
        wordlist = Wordlist.purge(wordlist)

        # return a list ['sub1', 'sub2', 'sub3', ...]
        if no_scan:
            return wordlist

        # constants
        len_wordlist = len(wordlist)
        max_len = 1
    
        # start with threads
        results = {}
        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
            results_executor = {executor.submit(Start.scan, max_len, domain, subdomain, wordlist.index(subdomain)/len_wordlist, results) for subdomain in wordlist}
        
        # return a dict
        return results

def main():
    domain = Start.arguments()
    
    # action: scan
    if not silent_mode: print (Start.logo())

    # wordlist
    if not silent_mode: Output.progressPrint("getting wordlist ...")
    local, remote = Wordlist.get(domain)

    # purge wordlist
    local = Wordlist.purge(local)
    remote = Wordlist.purge(remote)
    
    # mix wordlist local + remote
    wordlist = list(dict.fromkeys((local + remote)))
    wordlist = sorted(wordlist, key=str.lower)
    
    # purge wordlist
    wordlist = Wordlist.purge(wordlist)

    # takes the longest word in wordlist
    max_len = len(max(wordlist, key=len) + "." + domain) if wordlist else sys.exit("\nno wordlist")

    # no wordlist found
    if not wordlist: sys.exit("no wordlist")

    # if no-scan args show wordlist and exit
    if no_scan: 
        print (wordlist)
        sys.exit()

    # print header
    if not silent_mode: print (Output.headerPrint(local, remote, domain))
    
    # time start and print
    time_start = time.time()
    if not silent_mode: print (Output.headerBarPrint(time_start, max_len))
    
    # init
    len_wordlist = len(wordlist)
    results = {}
    
    # start with threads
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        results_executor = {executor.submit(Start.scan, max_len, domain, subdomain, wordlist.index(subdomain)/len_wordlist, results) for subdomain in wordlist}

        for item in concurrent.futures.as_completed(results_executor):
            if item.result() != None:
                # show line
                if not silent_mode: print (item.result())

    # elapsed time
    time_end = time.time()

    # show output
    if not silent_mode:
        # when silent_mode is False
        print (Output.footerPrint(time_end, time_start, results))
    elif silent_mode == "json":
        # json without indent
        print (json.dumps(results))
    elif silent_mode == "json-pretty":
        # json with indent
        print (json.dumps(results, indent=4))
    elif silent_mode == "csv":
        print (Report.csv(results))
    
    # when silent_mode is None (--silent without args) -> "no-output" -> quiet

    # save report
    if save_output: Report.save(results, domain, time_start, time_end, len_wordlist)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nInterrupted")
        try:
            sys.exit(0)
        except SystemExit:
            os._exit(0)
