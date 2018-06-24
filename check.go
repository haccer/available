package available

import (
	"fmt"
	"strings"

	"github.com/domainr/whois"
	"golang.org/x/net/publicsuffix"
)

/* SafeDomain utilizes the badtld checklist as a triage step,
then returns whether the domain is available and/or if the
domain has a "bad" tld.
*/
func SafeDomain(domain string) (available, badtld bool) {
	available = false

	domain = setDomain(domain)
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

/* Domain returns if the domain is available or not.
This function does not have a triage step, and will
result in testing each TLD with one of the default
responses.
*/
func Domain(domain string) (available bool) {
	available = false

	domain = setDomain(domain)
	tld, icann := publicsuffix.PublicSuffix(domain)

	if icann == true {
		query, err := publicsuffix.EffectiveTLDPlusOne(domain)
		if err != nil {
			return
		}

		available = match(tld, getWhois(query))
	}

	return available
}

func setDomain(domain string) string {
	if strings.Contains(domain, "://") {
		domain = strings.Split(domain, "://")[1]
	}

	if len(domain) > 1 {
		if domain[len(domain)-1:] == "." {
			domain = domain[:len(domain)-1]
		}
	}

	return strings.ToLower(domain)
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
