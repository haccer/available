package available

import (
	"io"
	"net"
	"strings"
	"sync"
	"time"
)

// ianaWhoisServer is the RFC 3912 bootstrap server used to discover the
// authoritative whois server for a TLD. It is a variable so tests can
// point it at a local fixture.
var ianaWhoisServer = "whois.iana.org:43"

var (
	whoisMu      sync.Mutex
	whoisServers = make(map[string]string)
)

// getWhois asks the authoritative whois server for a TLD about domain.
// This is the fallback for TLDs without RDAP support.
func getWhois(tld, domain string, timeout time.Duration) string {
	server := whoisServerFor(tld, timeout)
	if server == "" {
		return ""
	}
	return queryWhois(server, domain, timeout)
}

// whoisServerFor returns the authoritative whois server "host:port" for a
// TLD, looking it up via the IANA bootstrap server on first use and
// caching the result.
func whoisServerFor(tld string, timeout time.Duration) string {
	whoisMu.Lock()
	defer whoisMu.Unlock()

	if server, ok := whoisServers[tld]; ok {
		return server
	}

	resp := queryWhois(ianaWhoisServer, tld, timeout)
	for _, line := range strings.Split(resp, "\n") {
		// Referral lines look like "whois:      whois.verisign-grs.com".
		fields := strings.Fields(strings.ToLower(line))
		if len(fields) == 2 && fields[0] == "whois:" {
			server := net.JoinHostPort(fields[1], "43")
			whoisServers[tld] = server
			return server
		}
	}
	return ""
}

// queryWhois sends one query to a whois server and returns the response.
func queryWhois(addr, query string, timeout time.Duration) string {
	if timeout <= 0 {
		timeout = DefaultTimeout
	}

	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return ""
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(timeout))
	if _, err := conn.Write([]byte(query + "\r\n")); err != nil {
		return ""
	}

	data, err := io.ReadAll(conn)
	if err != nil {
		return string(data)
	}
	return string(data)
}
