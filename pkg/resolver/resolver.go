package resolver

import (
	"time"

	"github.com/miekg/dns"
)

// Resolver handles DNS resolution operations
type Resolver struct {
	Server  string
	Timeout time.Duration
}

// New creates a new DNS resolver
func New(server string, timeout time.Duration) *Resolver {
	if server == "" {
		server = "8.8.8.8:53"
	}
	if timeout == 0 {
		timeout = time.Second * 3
	}
	return &Resolver{
		Server:  server,
		Timeout: timeout,
	}
}

// Resolve attempts to resolve a domain name to an IP address
func (r *Resolver) Resolve(domain string) (string, error) {
	c := dns.Client{Timeout: r.Timeout}
	m := dns.Msg{}
	m.SetQuestion(dns.Fqdn(domain), dns.TypeA)

	res, _, err := c.Exchange(&m, r.Server)
	if err != nil {
		return "", err
	}

	if len(res.Answer) == 0 {
		return "", nil
	}

	for _, ans := range res.Answer {
		if a, ok := ans.(*dns.A); ok {
			return a.A.String(), nil
		}
	}

	return "", nil
}
