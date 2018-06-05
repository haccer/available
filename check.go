package available

import (
	"fmt"
	"strings"

	"github.com/domainr/whois"
	"golang.org/x/net/publicsuffix"
)

// Domain Returns if the domain is available (success) or if there's a badtld (fail)
func Domain(domain string) (available, badtld bool) {
	available = false

	if strings.Contains(domain, "://") {
		domain = strings.Split(domain, "://")[1]
	}

	domain = strings.ToLower(domain)

	tld, icann := publicsuffix.PublicSuffix(domain)
	badtld = badTLD(tld)

	if icann == true {
		query, err := publicsuffix.EffectiveTLDPlusOne(domain)
		if err != nil {
			return
		}

		if !badtld {
			available = match(tld, getWhois(query))
		}
	}

	return available, badtld
}

func match(tld, resp string) (available bool) {
	available = false

	fp := fingerprints()

	// .ca & .lt have opposite fingerprints
	if tld == "ca" || tld == "lt" {
		if !strings.Contains(resp, fp[tld]) {
			available = true
		}
	}

	/* Checks if the .tld is in our fingerprint list
	Then checks if the fingerprint is in the whois
	response data */
	if fp[tld] != "" {
		if strings.Contains(resp, fp[tld]) {
			available = true
		}
	} else {
		/* If the .tld isn't in our fingerprint list,
		this is the last resort options to check a
		list of possible responses.*/
		afp := all_fingerprints()

		for _, f := range afp {
			if strings.Contains(resp, f) {
				available = true
				break
			}
		}
	}

	return available
}

// Makes whois request, returns resposne as string
func getWhois(domain string) (response string) {
	req, err := whois.NewRequest(domain)
	if err != nil {
		return
	}

	resp, err := whois.DefaultClient.Fetch(req)
	if err != nil {
		return
	}

	return fmt.Sprintf("%s", resp)
}

// Checks if the TLD is apart of our "bad tld" list
func badTLD(tld string) (bad bool) {
	bad = false

	tlds := badtlds()

	for _, badtld := range tlds {
		if tld == badtld {
			bad = true
			break
		}
	}

	return bad
}
