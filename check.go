package available

import (
	"strings"
	"time"

	"golang.org/x/net/publicsuffix"
)

// DefaultTimeout is the timeout used by Domain and SafeDomain.
const DefaultTimeout = 10 * time.Second

// Domain reports whether the registrable domain under domain is
// unregistered. Any subdomain is reduced to its eTLD+1 first, so
// Domain("sub.example.com") checks "example.com".
//
// RDAP (RFC 9083) is consulted first: an authoritative 404 means the
// domain is not registered. TLDs without RDAP (and failed lookups) fall
// back to parsing a legacy whois response.
func Domain(domain string) bool {
	return DomainTimeout(domain, DefaultTimeout)
}

// DomainTimeout is Domain with a caller-supplied timeout.
func DomainTimeout(domain string, timeout time.Duration) bool {
	domain = setDomain(domain)
	if domain == "" {
		return false
	}

	tld, icann := publicsuffix.PublicSuffix(domain)
	if !icann {
		return false
	}

	query, err := publicsuffix.EffectiveTLDPlusOne(domain)
	if err != nil {
		return false
	}

	if available, ok := rdapAvailable(query, tld, timeout); ok {
		return available
	}

	return match(getWhois(tld, query, timeout))
}

/*
	SafeDomain utilizes the badtld checklist as a triage step,

then returns whether the domain is available and/or if the
domain has a "bad" tld.
*/
func SafeDomain(domain string) (available, badtld bool) {
	return SafeDomainTimeout(domain, DefaultTimeout)
}

// SafeDomainTimeout is SafeDomain with a caller-supplied timeout.
func SafeDomainTimeout(domain string, timeout time.Duration) (available, badtld bool) {
	domain = setDomain(domain)
	if domain == "" {
		return false, false
	}

	tld, icann := publicsuffix.PublicSuffix(domain)
	badtld = badTLD(tld)
	if !icann || badtld {
		return false, badtld
	}

	query, err := publicsuffix.EffectiveTLDPlusOne(domain)
	if err != nil {
		return false, badtld
	}

	if avail, ok := rdapAvailable(query, tld, timeout); ok {
		return avail, badtld
	}

	return match(getWhois(tld, query, timeout)), badtld
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

// genericFingerprints are "domain is available" substrings matched against
// legacy whois responses, line by line, case-insensitively and with
// whitespace runs collapsed to single spaces. They are the fallback for
// TLDs without RDAP support.
var genericFingerprints = []string{
	"domain not found",
	"domain is available",
	"is available for purchase",
	"is free",
	"name or service not known",
	"no data found",
	"no data was found",
	"no entries found",
	"no found",
	"no information available about domain name",
	"no match",
	"no matching record",
	"no object found",
	"no such domain",
	"not find matchingrecord",
	"not found",
	"nothing found",
	"not registered",
	"object does not exist",
	"object_not_found",
	"status: available",
	"status: free",
	"temporary failure in name resolution",
	"the domain has not been registered",
	"the queried object does not exist",
	"the requested domain was not found in the registry",
	"this domain name has not been registered",
	"this is not a registered domain",
	"was not found",
}

// match reports whether a whois response indicates the domain is
// available. Lines are matched individually so that unrelated fields on
// neighboring lines cannot combine into a fingerprint. An empty response
// means the query failed and is never treated as available.
func match(resp string) bool {
	if resp == "" {
		return false
	}

	for _, line := range strings.Split(strings.ToLower(resp), "\n") {
		line = strings.Join(strings.Fields(line), " ")
		for _, f := range genericFingerprints {
			if strings.Contains(line, f) {
				return true
			}
		}
	}
	return false
}

// badTLD reports whether a TLD has no usable whois/RDAP server.
func badTLD(tld string) bool {
	return badTLDs[tld]
}
