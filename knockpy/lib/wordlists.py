import os
import re
import time
from . import output
from importlib.machinery import SourceFileLoader

# purge wordlist
def purge(wordlist):
    return [word for word in wordlist if word and re.match("[a-z0-9\.-]", word)]

# get local dictionary
def localscan(filename):
    try:
        wlist = open(filename,'r').read().split("\n")
    except:
        if not silent_mode: output.progressPrint("wordlist not found: {filename}".format(filename=filename))
        return []
    return filter(None, wlist)

# get remote wordlist using plugin
def remotescan(domain):
    result = []

    # plugin_test is global variable
    if plugin_test:
        plugin_test_results = {}
        plugin_test_timeinit = time.time()
    
    for plugin in os.listdir(plugin_folder):
        
        # filter for .py scripts and exclude __init__.py file
        if plugin.endswith('.py') and plugin != '__init__.py':
            plugin_path = os.path.join(plugin_folder, plugin)
            
            try:
                # plugin_test is global variable
                if plugin_test:
                    plugin_test_timestart = time.time()

                if not silent_mode: 
                    output.progressPrint('') # print empty line
                    output.progressPrint(plugin) # print name of the module

                # load module
                foo = SourceFileLoader(plugin, plugin_path).load_module()
                
                # get module's result
                plugin_result = foo.get(domain)
                    
                if plugin_test:
                    # create dictionary with plugin info
                    plugin_time_elapsed = time.time() - plugin_test_timestart
                    plugin_time_elapsed = time.strftime("%H:%M:%S", time.gmtime(plugin_time_elapsed))
                    plugin_test_match = len(plugin_result)
                    plugin_test_results.update({plugin: {"time": plugin_time_elapsed, "match": plugin_test_match, "error": False}})

                # add subdomains
                result = result + plugin_result
            except:
                # print plugin error and sleep 3 secs.
                if not silent_mode: 
                    output.progressPrint("error plugin -> "+plugin)
                    time.sleep(3)
                
                if plugin_test:
                    plugin_time_elapsed = time.time() - plugin_test_timestart
                    plugin_time_elapsed = time.strftime("%H:%M:%S", time.gmtime(plugin_time_elapsed))
                    plugin_test_results.update({plugin: {"time": plugin_time_elapsed, "match": 0, "error": True}})

                continue
    
    result = list(set([r.lower() for r in result]))
    subdomains = [item.replace('.'+domain, '') for item in result]
    subdomains = purge(subdomains)
    
    # return test results
    if plugin_test:
        # add final results
        plugin_test_timeend = time.time() - plugin_test_timeinit
        plugin_test_timeend = time.strftime("%H:%M:%S", time.gmtime(plugin_test_timeend))
        plugin_test_error = [item for item in plugin_test_results.keys() if plugin_test_results[item]["error"]]
        plugin_test_list = list(plugin_test_results.keys())
        plugin_test_results.update({
            "_results": 
                {
                    "time": plugin_test_timeend,
                    "plugins": {
                        "count": len(plugin_test_list),
                        "list": plugin_test_list,
                        "error": plugin_test_error,
                        },                        
                    "subdomains": {
                        "count": len(subdomains),
                        "list": subdomains,
                        }
                }
            })
        return plugin_test_results
    
    return subdomains

# get wordlist local and/or remote
def get(domain, params):
    local, remote = [], []

    global silent_mode
    silent_mode = params["silent_mode"]
    global plugin_test
    plugin_test = params["plugin_test"]
    global local_wordlist
    local_wordlist = params["wordlist"]
    global plugin_folder
    plugin_folder = params["plugin_folder"]

    if not os.path.isfile(local_wordlist):
        return None, None

    if plugin_test:
        return remotescan(domain)

    if not params["no_local"]:
        local = list(localscan(local_wordlist))

    if not params["no_remote"]:
        remote = list(remotescan(domain))

    return local, remote