package scanner

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

type ReconScanner struct {
	config *Config
	client *http.Client
}

func NewReconScanner(config *Config) *ReconScanner {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   time.Duration(config.Timeout) * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	return &ReconScanner{config: config, client: client}
}

func (s *ReconScanner) Scan() ([]Result, error) {
	var results []Result
	var mu sync.Mutex
	var wg sync.WaitGroup
	seen := make(map[string]bool)

	// List of services to check
	services := []struct {
		name string
		url  string
	}{
		{"alienvault", fmt.Sprintf("https://otx.alienvault.com/api/v1/indicators/domain/%s/passive_dns", s.config.Domain)},
		{"crtsh", fmt.Sprintf("https://crt.sh/?q=%%25.%s&output=json", s.config.Domain)},
		{"hackertarget", fmt.Sprintf("https://api.hackertarget.com/hostsearch/?q=%s", s.config.Domain)},
		{"certspotter", fmt.Sprintf("https://api.certspotter.com/v1/issuances?domain=%s&include_subdomains=true&expand=dns_names", s.config.Domain)},
		{"webarchive", fmt.Sprintf("http://web.archive.org/cdx/search/cdx?url=*.%s/*&output=json&fl=original&collapse=urlkey", s.config.Domain)},
	}

	for _, service := range services {
		wg.Add(1)
		go func(name, url string) {
			defer wg.Done()

			resp, err := s.client.Get(url)
			if err != nil {
				return
			}
			defer resp.Body.Close()

			body, err := io.ReadAll(resp.Body)
			if err != nil {
				return
			}

			var subdomains []Result
			switch name {
			case "alienvault":
				var alienvaultResults struct {
					PassiveDNS []struct {
						Hostname string `json:"hostname"`
					} `json:"passive_dns"`
				}
				if err := json.Unmarshal(body, &alienvaultResults); err != nil {
					return
				}
				for _, result := range alienvaultResults.PassiveDNS {
					if strings.HasSuffix(result.Hostname, s.config.Domain) {
						mu.Lock()
						if !seen[result.Hostname] {
							seen[result.Hostname] = true
							subdomains = append(subdomains, Result{
								Subdomain: result.Hostname,
								Status:    "FOUND",
							})
						}
						mu.Unlock()
					}
				}
			case "webarchive":
				var webarchiveResults [][]string
				if err := json.Unmarshal(body, &webarchiveResults); err != nil {
					return
				}
				// Skip the header row
				if len(webarchiveResults) > 0 {
					webarchiveResults = webarchiveResults[1:]
				}
				for _, result := range webarchiveResults {
					if len(result) > 0 {
						// Extract hostname from URL by splitting
						urlParts := strings.Split(result[0], "//")
						if len(urlParts) > 1 {
							hostParts := strings.Split(urlParts[1], "/")
							if len(hostParts) > 0 {
								hostname := hostParts[0]
								if strings.HasSuffix(hostname, s.config.Domain) {
									mu.Lock()
									if !seen[hostname] {
										seen[hostname] = true
										subdomains = append(subdomains, Result{
											Subdomain: hostname,
											Status:    "FOUND",
										})
									}
									mu.Unlock()
								}
							}
						}
					}
				}
			case "certspotter":
				var certspotterResults []struct {
					DNSNames []string `json:"dns_names"`
				}
				if err := json.Unmarshal(body, &certspotterResults); err != nil {
					return
				}
				for _, result := range certspotterResults {
					for _, dnsName := range result.DNSNames {
						if strings.HasSuffix(dnsName, s.config.Domain) {
							mu.Lock()
							if !seen[dnsName] {
								seen[dnsName] = true
								subdomains = append(subdomains, Result{
									Subdomain: dnsName,
									Status:    "FOUND",
								})
							}
							mu.Unlock()
						}
					}
				}
			case "crtsh":
				var crtshResults []struct {
					NameValue string `json:"name_value"`
				}
				if err := json.Unmarshal(body, &crtshResults); err != nil {
					return
				}
				for _, result := range crtshResults {
					if strings.HasSuffix(result.NameValue, s.config.Domain) {
						mu.Lock()
						if !seen[result.NameValue] {
							seen[result.NameValue] = true
							subdomains = append(subdomains, Result{
								Subdomain: result.NameValue,
								Status:    "FOUND",
							})
						}
						mu.Unlock()
					}
				}
			case "hackertarget":
				lines := strings.Split(string(body), "\n")
				for _, line := range lines {
					if line == "" {
						continue
					}
					parts := strings.Split(line, ",")
					if len(parts) >= 1 && strings.HasSuffix(parts[0], s.config.Domain) {
						mu.Lock()
						if !seen[parts[0]] {
							seen[parts[0]] = true
							subdomains = append(subdomains, Result{
								Subdomain: parts[0],
								Status:    "FOUND",
							})
						}
						mu.Unlock()
					}
				}
			}

			for _, subdomain := range subdomains {
				if result, err := s.checkDomain(subdomain.Subdomain); err == nil {
					mu.Lock()
					results = append(results, *result)
					mu.Unlock()
				}
			}
		}(service.name, service.url)
	}

	wg.Wait()
	return results, nil
}

func (s *ReconScanner) checkDomain(domain string) (*Result, error) {
	result := &Result{
		Subdomain: domain,
		Status:    "FOUND",
	}

	// Resolve IP addresses
	ips, err := net.LookupHost(domain)
	if err != nil {
		return nil, err
	}
	result.IPs = ips

	// Check HTTP
	httpStatus, err := s.checkHTTP(domain, false)
	if err == nil {
		result.HTTP = httpStatus
	}

	// Check HTTPS
	httpsStatus, err := s.checkHTTP(domain, true)
	if err == nil {
		result.HTTPS = httpsStatus
	}

	// Check certificate
	if httpsStatus != nil {
		certInfo, err := s.checkCertificate(domain)
		if err == nil {
			result.Certificate = certInfo
		}
	}

	return result, nil
}

func (s *ReconScanner) checkHTTP(domain string, isHTTPS bool) (*HTTPStatus, error) {
	scheme := "http"
	if isHTTPS {
		scheme = "https"
	}
	
	url := fmt.Sprintf("%s://%s", scheme, domain)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	if s.config.UserAgent != "" {
		req.Header.Set("User-Agent", s.config.UserAgent)
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	status := &HTTPStatus{
		StatusCode: resp.StatusCode,
		Location:   resp.Header.Get("Location"),
		Server:     resp.Header.Get("Server"),
	}

	return status, nil
}

func (s *ReconScanner) checkCertificate(domain string) (*CertInfo, error) {
	conn, err := tls.Dial("tcp", domain+":443", &tls.Config{
		InsecureSkipVerify: true,
	})
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	cert := conn.ConnectionState().PeerCertificates[0]
	now := time.Now()

	return &CertInfo{
		Valid:      now.Before(cert.NotAfter),
		ExpiryDate: cert.NotAfter.Format(time.RFC3339),
		CommonName: cert.Subject.CommonName,
	}, nil
}
