package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/rasperon/knock-go/pkg/scanner"
)

func main() {
	config := scanner.NewConfig()

	flag.StringVar(&config.Domain, "domain", "", "Domain to analyze")
	flag.StringVar(&config.DNS, "dns", "8.8.8.8:53", "Custom DNS server")
	flag.StringVar(&config.UserAgent, "useragent", "", "Custom User-Agent")
	flag.IntVar(&config.Timeout, "timeout", 3, "Timeout in seconds")
	flag.IntVar(&config.Threads, "threads", 10, "Number of concurrent threads")
	flag.StringVar(&config.WordlistPath, "wordlist", "", "Custom wordlist file")
	flag.StringVar(&config.SavePath, "save", "", "Folder to save results")

	recon := flag.Bool("recon", false, "Perform subdomain reconnaissance")
	bruteforce := flag.Bool("bruteforce", false, "Perform subdomain bruteforce")

	flag.Parse()

	if config.Domain == "" {
		fmt.Println("Error: domain is required")
		flag.Usage()
		os.Exit(1)
	}

	var results []scanner.Result

	// Perform reconnaissance if requested
	if *recon {
		fmt.Println("Starting reconnaissance...")
		reconScanner := scanner.NewReconScanner(config)
		reconResults, err := reconScanner.Scan()
		if err != nil {
			fmt.Printf("Error during reconnaissance: %v\n", err)
		} else {
			results = append(results, reconResults...)
		}
	}

	// Perform bruteforce if requested
	if *bruteforce {
		fmt.Println("Starting bruteforce...")
		bruteforceScanner := scanner.NewBruteforceScanner(config)
		bruteforceResults, err := bruteforceScanner.Scan()
		if err != nil {
			fmt.Printf("Error during bruteforce: %v\n", err)
		} else {
			results = append(results, bruteforceResults...)
		}
	}

	// Save or display results
	if config.SavePath != "" {
		if err := saveResults(config.SavePath, config.Domain, results); err != nil {
			fmt.Printf("Error saving results: %v\n", err)
		}
	} else {
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetIndent("", "  ")
		encoder.Encode(results)
	}
}

func saveResults(folder, domain string, results []scanner.Result) error {
	if err := os.MkdirAll(folder, 0755); err != nil {
		return fmt.Errorf("error creating output directory: %v", err)
	}

	filename := filepath.Join(folder, fmt.Sprintf("%s_%s.json", domain, time.Now().Format("20060102_150405")))
	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("error creating output file: %v", err)
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(results); err != nil {
		return fmt.Errorf("error encoding results: %v", err)
	}

	fmt.Printf("Results saved to: %s\n", filename)
	return nil
}
