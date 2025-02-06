package wordlist

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// Loader handles loading and processing of wordlists
type Loader struct {
	Path string
}

// New creates a new wordlist loader
func New(path string) *Loader {
	return &Loader{Path: path}
}

// Load reads the wordlist file and returns a slice of subdomains
func (l *Loader) Load(domain string) ([]string, error) {
	file, err := os.Open(l.Path)
	if err != nil {
		return nil, fmt.Errorf("error opening wordlist: %v", err)
	}
	defer file.Close()

	var subdomains []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		word := strings.TrimSpace(scanner.Text())
		if word != "" {
			subdomains = append(subdomains, fmt.Sprintf("%s.%s", word, domain))
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading wordlist: %v", err)
	}

	return subdomains, nil
}

// DefaultWordlist returns a basic set of common subdomain prefixes
func DefaultWordlist(domain string) []string {
	prefixes := []string{
		"www", "mail", "ftp", "admin", "blog", "dev", "test",
		"staging", "api", "docs", "support", "portal", "cdn",
	}

	subdomains := make([]string, len(prefixes))
	for i, prefix := range prefixes {
		subdomains[i] = fmt.Sprintf("%s.%s", prefix, domain)
	}

	return subdomains
}
