package tests

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/rasperon/knock-go/pkg/scanner"
)

func TestKnockGo(t *testing.T) {
	// Test configuration
	config := &scanner.Config{
		Domain:     "github.com",
		DNS:        "8.8.8.8",
		UserAgent:  "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:33.0) Gecko/20120101 Firefox/33.0",
		Timeout:    2,
		Threads:    10,
		Recon:      true,
		Bruteforce: true,
	}

	// Create scanner instances
	reconScanner := scanner.NewReconScanner(config)
	bruteforceScanner := scanner.NewBruteforceScanner(config)

	// Run recon scan
	reconResults, err := reconScanner.Scan()
	if err != nil {
		t.Errorf("Recon scan failed: %v", err)
		return
	}

	// Run bruteforce scan
	bruteforceResults, err := bruteforceScanner.Scan()
	if err != nil {
		t.Errorf("Bruteforce scan failed: %v", err)
		return
	}

	// Combine results
	allResults := append(reconResults, bruteforceResults...)

	// Print results as JSON
	resultsJSON, err := json.MarshalIndent(allResults, "", "  ")
	if err != nil {
		t.Errorf("Failed to marshal results: %v", err)
		return
	}

	fmt.Printf("Results:\n%s\n", string(resultsJSON))

	// Basic validation
	if len(allResults) == 0 {
		t.Error("No subdomains found")
		return
	}

	// Check if github.com is in results
	found := false
	for _, result := range allResults {
		if result.Subdomain == "github.com" {
			found = true
			break
		}
	}
	if !found {
		t.Error("Main domain github.com not found in results")
	}
}
