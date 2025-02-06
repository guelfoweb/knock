Here is the English translation of the provided Markdown file:

# Features

* **Passive reconnaissance** services used:
  - CertSpotter
  - crt.sh
  - HackerTarget
* **Active subdomain brute-force** scanning
* **Concurrent scanning** (customizable thread count)
* **JSON output format**
* **Customizable DNS resolver**
* **Custom User-Agent support**
* **Save results** feature

# Installation
```bash
# / Clone the repository
git clone https://github.com/rasperon/knock-go.git
cd knock-go

# Download dependencies
go mod download

# Build the binary
go build -o knock-go
```

# Usage
```
 ./knock-go:
  -bruteforce
        Perform subdomain bruteforce
  -dns string
        Custom DNS server (default "8.8.8.8:53")
  -domain string
        Domain to analyze
  -recon
        Perform subdomain reconnaissance
  -save string
        Folder to save results
  -threads int
        Number of concurrent threads (default 10)
  -timeout int
        Timeout in seconds (default 3)
  -useragent string
        Custom User-Agent
  -wordlist string
        Custom wordlist file
```
```bash
./knock-go -domain example.com -recon
./knock-go -domain example.com -bruteforce
./knock-go -domain example.com -recon -bruteforce -threads 20 -timeout 5 -dns 1.1.1.1:53 -save results
```

# Output
The tool generates output in JSON format and saves it to a file when the -save option is used. The output includes the following information:

    Subdomain
    Source
    Scan type (Passive/Bruteforce)

# Disclaimer
This tool is intended for educational and ethical hacking purposes only. Use it responsibly and only on systems where you have permission to test. I am not responsible for any misuse of this tool.

# Contributing
Contributions are welcome! Please submit pull requests for bug fixes, improvements, or new features.

# License
[GPU License](LICENSE)