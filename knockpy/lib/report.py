import os
import time
import json
from . import output

user_agent = [
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.14; rv:65.0) Gecko/20100101 Firefox/65.0",
    "Mozilla/5.0 (MSIE 10.0; Windows NT 6.1; Trident/5.0)",
    "Opera/9.80 (Windows NT 6.0) Presto/2.12.388 Version/12.14",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_3) AppleWebKit/537.75.14 (KHTML, like Gecko) Version/7.0.3 Safari/7046A194A"
]

# import json file
def load_json(report):
    try:
        report_json = json.load(open(report))
        del report_json["_meta"]
        return report_json
    except:
        return None

# save output and add _meta to json file
def save(results, domain, time_start, time_end, len_wordlist, version, output_folder):
    _meta = {
        "name": "knockpy",
        "version": version,
        "time_start": time_start,
        "time_end": time_end,
        "domain": domain,
        "wordlist": len_wordlist
        }
    
    results.update({"_meta": _meta})
    strftime = "%Y_%m_%d_%H_%M_%S"
    date = time.strftime(strftime, time.gmtime(time_end)) 
    path = output_folder + os.sep + domain + "_" + date + ".json"
    output.write_json(path, results)

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
    report_json = load_json(domain)
    
    # report not found or invalid json
    if report_json == None: 
        return None

    results = ""
    for item in report_json.keys():
        report_json[item].update({"target": item})
        max_len = len(max(list(report_json.keys()), key=len))
        results += output.linePrint(report_json[item], max_len) + "\n"
    return results

# plotting relationships
def plot(report):
    # todo:
    # get modules list from sys.modules.keys()
    try:
        import matplotlib.pyplot as plt
        import networkx as nx
    except:
        return None


    dataset = []
    for item in report.keys():
        dataset.append((report[item]["ipaddr"][0], item))

    g = nx.Graph()
    g.add_edges_from(dataset)

    pos = nx.spring_layout(g)
    nx.draw(g, pos, node_size=50, node_color="r", edge_color="c", with_labels=True, width=0.7, alpha=0.9)
    plt.show()