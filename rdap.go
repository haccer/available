package available

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/idna"
)

// rdapBootstrapURL is the IANA service that maps TLDs to their RDAP base
// URLs (https://data.iana.org/rdap/dns.json). It is a variable so tests
// can point it at a local fixture.
var rdapBootstrapURL = "https://data.iana.org/rdap/dns.json"

var rdapClient = &http.Client{}

var (
	rdapMu       sync.Mutex
	rdapServers  = map[string]string{} // tld -> RDAP base URL
	rdapResolved bool                  // bootstrap fetched (successfully or not)
)

// rdapAvailable asks the TLD's RDAP server about a domain. ok is false
// when RDAP cannot answer — no server for the TLD, a transport error, or
// a non-definitive status — and the caller should fall back to whois.
//
// Per RFC 9083 the answer is carried by the HTTP status itself:
// 404 means no such registered object (the domain is available) and 200
// means the domain is registered.
func rdapAvailable(domain, tld string, timeout time.Duration) (available, ok bool) {
	base, err := rdapBaseURL(tld, timeout)
	if err != nil || base == "" {
		return false, false
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/domain/"+domain, nil)
	if err != nil {
		return false, false
	}
	req.Header.Set("Accept", "application/rdap+json")
	req.Header.Set("User-Agent", "haccer-available")

	resp, err := rdapClient.Do(req)
	if err != nil {
		return false, false
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusNotFound:
		return true, true
	case http.StatusOK:
		return false, true
	default:
		// Rate limits (429), server errors, blocked queries: no answer.
		return false, false
	}
}

// rdapBaseURL resolves the RDAP base URL for a TLD, fetching the IANA
// bootstrap file once per process. It returns "" for TLDs without RDAP.
func rdapBaseURL(tld string, timeout time.Duration) (string, error) {
	rdapMu.Lock()
	defer rdapMu.Unlock()

	if !rdapResolved {
		err := loadRDAPBootstrap(timeout)
		rdapResolved = true // cache failures too; whois covers the gap
		if err != nil {
			return "", err
		}
	}

	if base, ok := rdapServers[tld]; ok {
		return base, nil
	}

	// IDN TLDs are listed in the bootstrap file in punycode.
	if ascii, err := idna.ToASCII(tld); err == nil {
		return rdapServers[ascii], nil
	}
	return "", nil
}

// loadRDAPBootstrap fetches and parses the IANA RDAP bootstrap file. Each
// service entry is [tld-list, url-list]; the first https URL wins.
func loadRDAPBootstrap(timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rdapBootstrapURL, nil)
	if err != nil {
		return err
	}

	resp, err := rdapClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("rdap bootstrap: unexpected status %d", resp.StatusCode)
	}

	var services [][][]string
	if err := json.NewDecoder(resp.Body).Decode(&services); err != nil {
		return err
	}

	for _, svc := range services {
		if len(svc) < 2 || len(svc[0]) == 0 {
			continue
		}

		base := ""
		for _, url := range svc[1] {
			if strings.HasPrefix(url, "https://") {
				base = strings.TrimSuffix(url, "/")
				break
			}
		}
		if base == "" && len(svc[1]) > 0 {
			base = strings.TrimSuffix(svc[1][0], "/")
		}

		for _, tld := range svc[0] {
			tld = strings.ToLower(strings.TrimPrefix(tld, "."))
			rdapServers[tld] = base
		}
	}
	return nil
}
