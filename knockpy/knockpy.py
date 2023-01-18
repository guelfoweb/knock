#!/usr/bin/python3
# -*- coding: utf-8 -*-

from argparse import RawTextHelpFormatter
import concurrent.futures
import argparse
from knockpy.lib import output, request, wordlists, report, scan, extraargs, logo
import random
import time
import json
import sys
import re
import os

__version__ = "6.1.0"

user_agent = [
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.14; rv:65.0) Gecko/20100101 Firefox/65.0",
    "Mozilla/5.0 (MSIE 10.0; Windows NT 6.1; Trident/5.0)",
    "Opera/9.80 (Windows NT 6.0) Presto/2.12.388 Version/12.14",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_3) AppleWebKit/537.75.14 (KHTML, like Gecko) Version/7.0.3 Safari/7046A194A"
]

_ROOT = os.path.abspath(os.path.dirname(__file__))
_local_wordlist = _ROOT + "{sep}local{sep}wordlist.txt".format(sep=os.sep)
_remote_plugin_folder = _ROOT + '{sep}remote'.format(sep=os.sep)
_user_agent = random.choice(user_agent)

# default params
_params = {
    "no_local": False,                      # [bool] local wordlist ignore --no-local
    "no_remote": False,                     # [bool] remote wordlist ignore --no-remote
    "no_scan": False,                       # [bool] scanning ignore, show wordlist --no-scan
    "no_http": False,                       # [bool] http requests ignore --no-http
    "no_http_code": [],                     # [list] http code list to ignore --no-http-code 404
    "no_ip": [],                            # [list] ip address to ignore --no-ip 127.0.0.1
    "dns": "",                              # [str] use custom DNS ex. 8.8.8.8 --dns 8.8.8.8
    "timeout": 3,                           # [int] timeout in seconds -t 5
    "threads": 30,                          # [int] threads num -th 50
    "useragent": _user_agent,               # [str] use a custom user agent --user-agent Mozilla
    "wordlist": _local_wordlist,            # [str] path to custom wordlist -w file.txt
    "silent_mode": False,                   # [bool] silent mode --silent (--silent csv)
    "output_folder": "knockpy_report",      # [str] report folder -o /folder/
    "save_output": True,                    # [bool] save report -o false to disable it
    "plugin_test": False,                   # [bool] test plugin --plugin-test
    "plugin_folder": _remote_plugin_folder  # [str] plugin folder (no via arg)
}

# check for valid domain
def is_valid_domain(domain):
    if not isinstance(domain, str) or not re.match("[a-z0-9\.-]", domain) or domain.startswith(("http", "www.")):
        return False
    return True

"""
# module to import in python script:

from knockpy import knockpy

# return json results
results = knockpy.Scanning.start("domain.com", params)
"""
class Scanning:
    def start(domain, params=False):
        # params validation
        if not params:
            params = _params
        else:
            for param in _params.keys():
                value = _params[param]
                if param not in params:
                    params.update({param: value})

        if params["no_local"] and params["no_remote"]: # case no wordlist
            return None
    
        # global flags by default
        params["silent_mode"] = "json"
        params["output_folder"] = False

        # get wordlist
        if params["plugin_test"]:
            return wordlists.get(domain, params)

        local, remote = wordlists.get(domain, params)
        
        # local wordlist not found
        if local == None: return None

        # get wordlists
        local, remote, wordlist = Start.wordlist(domain, params)

        # return a list ['sub1', 'sub2', 'sub3', ...]
        if params["no_scan"]:
            return wordlist

        # max_len default value. 
        # it is not necessary to assign a correct value
        # when working as a module
        max_len = 1

        # start scan
        return Start.threads(domain, max_len, wordlist, params)

class Start():
    # print random message
    def msg_rnd():
        return ["happy hacking ;)", "good luck!", "never give up!",
                "hacking is not a crime", "https://en.wikipedia.org/wiki/Bug_bounty_program"]

    def arguments():
        # check for extra arguments
        extraargs.parse_and_exit(sys.argv)

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

        # args
        parser.add_argument("domain", nargs='?', help="target to scan", default=sys.stdin, type=str)
        parser.add_argument("-v", "--version", action="version", version="%(prog)s " + __version__)
        parser.add_argument("--no-local", help="local wordlist ignore", action="store_true", required=False)
        parser.add_argument("--no-remote", help="remote wordlist ignore", action="store_true", required=False)
        parser.add_argument("--no-scan", help="scanning ignore, show wordlist and exit", action="store_true", required=False)
        parser.add_argument("--no-http", help="http requests ignore\n\n", action="store_true", required=False)
        parser.add_argument("--no-http-code", help="http code list to ignore\n\n", nargs="+", dest="code", type=int, required=False)
        parser.add_argument("--no-ip", help="ip address to ignore\n\n", nargs="+", type=str, required=False)
        parser.add_argument("--dns", help="use custom DNS ex. 8.8.8.8\n\n", dest="dns", required=False)
        parser.add_argument("--user-agent", help="use a custom user agent\n\n", dest="useragent", required=False)
        parser.add_argument("--plugin-test", help="test plugins and exit\n\n", action="store_true", required=False)

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
        if args.no_ip:
            _params["no_ip"] = args.no_ip

        # --no-scan ignore scanning
        if args.no_scan:
            _params["no_scan"] = args.no_scan
        
        # --silent set silent mode
        """
        silent_mode is False by default.
        --silent without args -> the value is None, then I change it in "no-output"
        --silent with args -> it keep argument passed, ex: --silent csv
        """
        if args.silent:
            _params["silent_mode"] = args.silent
        elif args.silent == None:
           _params["silent_mode"] = "no-output"

        # get domain name via positional argument or stdin
        if sys.stdin.isatty():
            # positional
            # knockpy domain.com
            domain = args.domain
        else:
            # stdin
            # echo "domain.com" | knockpy
            domain = args.domain.read()
            domain = domain.strip()
            
        # check if the domain name is correct
        if not is_valid_domain(domain):
            parser.print_help(sys.stderr)
            sys.exit()

        # --no-local exclude local dictionary
        if args.no_local:
            _params["no_local"] = args.no_local

        # --no-remote exclude remote dictionary
        if args.no_remote:
            _params["no_remote"] = args.no_remote

        # choice wordlist
        if _params["no_local"] and _params["no_remote"]: sys.exit("no wordlist")
        
        # --no-http ignore requests
        if args.no_http:
            _params["no_http"] = args.no_http
        
        # --no-http-code ignore http code
        if args.code:
            _params["no_http"] = args.code

        # -o set report folder
        if args.folder:
            _params["output_folder"] = args.folder

        # check that the "-o false" parameter was not supplied
        if _params["output_folder"] != "false":
            # create folder if not exists
            if not os.path.exists(_params["output_folder"]): os.makedirs(_params["output_folder"])
            # check if the folder is accessible
            if not os.access(_params["output_folder"], os.W_OK): sys.exit("folder not exists or not writable: " + _params["output_folder"])
        
        # save output depends on the -o option
        # it's True by default except when "-o false"
        if _params["output_folder"].lower() == "false":
            _params["save_output"] = False

        # -t set timeout default is 3
        if args.sec:
            _params["timeout"] = args.sec

        # -th set threads default is 30
        if args.num:
            _params["threads"] = args.num

        # -w set path to local wordlist default is "wordlist.txt"
        if args.wordlist:
            _params["wordlist"] = args.wordlist

        # --dns set dns default is False
        if args.dns:
            _params["dns"] = args.dns

        # --user-agent
        if args.useragent:
            _params["useragent"] = args.useragent

        # --plugin-test
        if args.plugin_test:
            _params["plugin_test"] = args.plugin_test

        return domain, _params

    # Start scan via "scan.start" module in lib/
    def threads(domain, max_len, wordlist, params):
        len_wordlist = len(wordlist)
        results = {}

        # start with threads
        with concurrent.futures.ThreadPoolExecutor(max_workers=params["threads"]) as executor:
            results_executor = {executor.submit(scan.start, max_len, domain, subdomain, wordlist.index(subdomain)/len_wordlist, results, params) for subdomain in wordlist}

            if not params["silent_mode"]:
                for item in concurrent.futures.as_completed(results_executor):
                    if item.result() != None:
                        print (item.result())
        # return a dict
        return results

    def wordlist(domain, params):
        # get wordlist
        local, remote = wordlists.get(domain, params)

        # case local wordlist not found
        if local == None and remote == None:
            return [], [], []

        local = wordlists.purge(local)
        remote = wordlists.purge(remote)
        
        # join wordlist local + remote
        wordlist = list(dict.fromkeys((local + remote)))
        wordlist = sorted(wordlist, key=str.lower)
        wordlist = wordlists.purge(wordlist)
        return local, remote, wordlist

def main():
    domain, params = Start.arguments()

    # action: scan
    if not params["silent_mode"]:
        print (logo.show(__version__))
        output.progressPrint("getting wordlist ...")

    # get wordlist
    if params["plugin_test"]:
        print (wordlists.get(domain, params))
        sys.exit()
    
    # get wordlists
    local, remote, wordlist = Start.wordlist(domain, params)

    # takes the longest word in wordlist
    max_len = len(max(wordlist, key=len) + "." + domain) if wordlist else sys.exit("\nno wordlist")

    # if no-scan args show wordlist and exit
    if params["no_scan"]: 
        print (wordlist)
        sys.exit()

    # print header
    if not params["silent_mode"]: 
        print (output.headerPrint(local, remote, domain))
    
    # time start and print
    time_start = time.time()
    if not params["silent_mode"]: 
        print (output.headerBarPrint(time_start, max_len, params["no_http"]))
    
    # Start threads
    results = Start.threads(domain, max_len, wordlist, params)

    # elapsed time
    time_end = time.time()

    # show output
    # when silent_mode is None (--silent without args) -> "no-output" -> quiet
    if not params["silent_mode"]:
        # when silent_mode is False
        print (output.footerPrint(time_end, time_start, results))
    elif params["silent_mode"] == "json":
        # json without indent
        print (json.dumps(results))
    elif params["silent_mode"] == "json-pretty":
        # json with indent
        print (json.dumps(results, indent=4))
    elif params["silent_mode"] == "csv":
        print (report.csv(results))

    # save report
    if params["save_output"]: 
        report.save(results, domain, time_start, time_end, len(wordlist), __version__, params["output_folder"])

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nInterrupted")
        try:
            sys.exit(0)
        except SystemExit:
            os._exit(0)
