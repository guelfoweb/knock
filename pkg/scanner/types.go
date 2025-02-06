package scanner

// Result represents a single subdomain scan result
type Result struct {
	Subdomain string `json:"subdomain"`
	Status    string `json:"status"`
	IPs       []string `json:"ips,omitempty"`
	HTTP      *HTTPStatus `json:"http,omitempty"`
	HTTPS     *HTTPStatus `json:"https,omitempty"`
	Certificate *CertInfo `json:"certificate,omitempty"`
}

// Config holds the scanner configuration
type Config struct {
	Domain     string
	DNS        string
	UserAgent  string
	Timeout    int
	Threads    int
	WordlistPath string
	SavePath   string
	Recon      bool
	Bruteforce bool
}

type HTTPStatus struct {
	StatusCode int    `json:"status_code,omitempty"`
	Location   string `json:"redirect_location,omitempty"`
	Server     string `json:"server,omitempty"`
}

type CertInfo struct {
	Valid      bool   `json:"valid"`
	ExpiryDate string `json:"expiry_date,omitempty"`
	CommonName string `json:"common_name,omitempty"`
}

// NewConfig creates a new scanner configuration with default values
func NewConfig() *Config {
	return &Config{
		DNS:     "8.8.8.8",
		Timeout: 3,
		Threads: 10,
	}
}
