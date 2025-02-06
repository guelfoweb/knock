package scanner

import (
	"bufio"
	"fmt"
	"os"
	"sync"

	"github.com/schollz/progressbar/v3"
)

// BruteforceScanner handles bruteforce scanning operations
type BruteforceScanner struct {
	config   *Config
	recon    *ReconScanner // Add ReconScanner for domain checking
}

// NewBruteforceScanner creates a new bruteforce scanner
func NewBruteforceScanner(config *Config) *BruteforceScanner {
	return &BruteforceScanner{
		config: config,
		recon:  NewReconScanner(config), // Initialize ReconScanner
	}
}

func (s *BruteforceScanner) loadWordlist() ([]string, error) {
	wordlistPath := s.config.WordlistPath
	if wordlistPath == "" {
		wordlistPath = "wordlist.txt" // Default wordlist in current directory
	}

	file, err := os.Open(wordlistPath)
	if err != nil {
		return nil, fmt.Errorf("error opening wordlist: %v", err)
	}
	defer file.Close()

	var words []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		word := scanner.Text()
		if word != "" {
			words = append(words, word)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading wordlist: %v", err)
	}

	if len(words) == 0 {
		// Fallback to default subdomains if wordlist is empty
		words = []string{"www", "mail", "ftp", "admin", "blog", "dev", "test", "staging"}
	}

	return words, nil
}

// Scan performs bruteforce scanning using a wordlist
func (s *BruteforceScanner) Scan() ([]Result, error) {
	words, err := s.loadWordlist()
	if err != nil {
		fmt.Printf("Warning: %v, using default subdomains\n", err)
		words = []string{"www", "mail", "ftp", "admin", "blog", "dev", "test", "staging"}
	}

	var results []Result
	var mu sync.Mutex
	var wg sync.WaitGroup
	semaphore := make(chan struct{}, s.config.Threads)

	// Create progress bar
	bar := progressbar.Default(int64(len(words)), "Bruteforcing subdomains")

	// Start bruteforce
	for _, word := range words {
		wg.Add(1)
		semaphore <- struct{}{} // Acquire semaphore

		subdomain := fmt.Sprintf("%s.%s", word, s.config.Domain)
		go func(subdomain string) {
			defer wg.Done()
			defer func() { <-semaphore }() // Release semaphore
			defer bar.Add(1)

			if result, err := s.recon.checkDomain(subdomain); err == nil {
				mu.Lock()
				results = append(results, *result)
				mu.Unlock()
			}
		}(subdomain)
	}

	wg.Wait()
	return results, nil
}
