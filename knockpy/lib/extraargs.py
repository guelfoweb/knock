import os
import sys
from . import report
from . import output

# extra arguments ["--report", "--plot", "--csv"]
# when domain not is a domain name but it's a command
def parse_and_exit(args):
    if len(args) == 3 and args[1] in ["--report", "--plot", "--csv"]:

        # report
        if args[1] == "--report":
            if args[2].endswith(".json"):
                if os.path.isfile(args[2]):
                    data = report.terminal(args[2])
                    if not data:
                        sys.exit("report not found or invalid json")
                    if data: sys.exit(data)
                sys.exit("report not found: %s" % args[2])
            sys.exit("try using: knockpy --report path/to/domain.com_yyyy_mm_dd_hh_mm_ss.json")

        # plot
        elif args[1] == "--plot":
            if args[2].endswith(".json"):
                if os.path.isfile(args[2]):
                    data = report.load_json(args[2])
                    if not data:
                        sys.exit("report not found or invalid json")
                    if data: 
                        plotting = report.plot(data)
                        if not plotting:
                            print("Plot needs these libraries. Use 'pip' to install them:\n- matplotlib\n- networkx\n- PyQt5")
                    sys.exit()
                sys.exit("report not found: %s" % args[2])
            sys.exit("try using: knockpy --plot path/to/domain.com_yyyy_mm_dd_hh_mm_ss.json")

        # csv
        elif args[1] == "--csv":
            if args[2].endswith(".json"):
                if os.path.isfile(args[2]):
                    data = report.load_json(args[2])
                    if data: 
                        csv_file = args[2].replace(".json", ".csv")
                        output.write_csv(csv_file, report.csv(data))
                        sys.exit("csv report: %s" % csv_file)
                sys.exit("report not found: %s" % args[2])
            sys.exit("try using: knockpy --csv path/to/domain.com_yyyy_mm_dd_hh_mm_ss.json")