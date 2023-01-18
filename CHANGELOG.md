# Changelog

6.1.0 - 2023-01-18
---------
- added plugin test --plugin-test
- added new plugin: api_censys, certsh
- fixed plugin scan loop
- optimized code structure

6.0.0 - 2023-01-15
---------
- added silent mode --silent
- added ignore scanning --no-scan
- added api_shodan and api_virustotal to plugin
- added custom user agent --user-agent
- added callable python module (Scanning.start())
- added stdin
- changed passive folder to remote
- moved wordlist.txt to local folder
- deleted --set
- optimized some parts of the code

5.4.0 - 2023-01-09
---------
- added passive reconnaissance plugins

5.3.0 - 2022-03-03
---------
- added custom dns --dns

5.2.0 - 2021-10-03
---------
- added asynchronous execution

5.1.0 - 2021-03-31
---------
- added show report --report
- added csv report --csv
- added plot report --plot
- added set apikey --set apikey-virustotal=

5.0.0 - 2021-03-20
---------
- rewriting code in python 3.

4.1.1 - 2017-09-05
---------
- added -f or --csvfileds option to add fields name to the first row of csv output file.

4.1 - 2017-08-07
---------
- added VirusTotal support. Setting the API_KEY within the config.json file.

4.0 - 2017-02-03
---------
- release v.4.0.0

4.0 beta - 2016-12-16
---------

- rewrited code and options
- removed option -z
- new -c or --csv option to export CSV output
- new -j or --json option to export full output in JSON

3.0 rc1 - 2014-02-21
---------
- release v.3.0 rc1

2.0 - 2014-02-20
---------
- rewrite code and options
- detect ALIAS name
- automatic wildcard bypass
- resolve single domain

1.x - 2011
---------
- old version on Google Code -> http://code.google.com/p/knock/
