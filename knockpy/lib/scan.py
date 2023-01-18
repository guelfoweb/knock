from . import output
from . import request

def start(max_len, domain, subdomain, percentage, results, params):
    ctrl_c = "(ctrl+c) | "

    #output.progressPrint(ctrl_c + subdomain)
    target = subdomain+"."+domain
    if not params["silent_mode"]: output.progressPrint(ctrl_c + str(percentage*100)[:4] + "% | " + target + " "*max_len)
    req = request.dns(target, params["dns"])

    if not req: return None

    req = list(req)
    ip_req = req[2][0]

    if ip_req in params["no_ip"]: return None

    # dns only
    if params["no_http"]:
        # print line and update report
        data = output.jsonizeRequestData(req, target)
        if not params["silent_mode"]: print (output.linePrint(data, max_len))
        del data["target"]
        return results.update({target: data})

    # dns and http(s)
    https = request.https(target, params["useragent"])
    
    if https:
        for item in https:
            req.append(item)
    else:
        http = request.http(target, params["useragent"])
        
        if http:
            for item in http:
                req.append(item)
        else:
            req.append("")
            req.append("")

    # print line and update report
    data = output.jsonizeRequestData(req, target)
    if data["code"] in params["no_http_code"]: return None
    if not params["silent_mode"]: print (output.linePrint(data, max_len))
    del data["target"]
    
    return results.update({target: data})