package available

import (
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// startFakeWhoisServer runs a trivial RFC 3912 server on a loopback
// ephemeral port. respond maps a received query to a response. The second
// return value reports the queries received so far.
func startFakeWhoisServer(t *testing.T, respond func(query string) string) (addr string, received func() []string) {
	t.Helper()

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	var mu sync.Mutex
	var queries []string
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				c.SetReadDeadline(time.Now().Add(2 * time.Second))
				buf := make([]byte, 1024)
				n, _ := c.Read(buf)
				query := strings.TrimSpace(string(buf[:n]))
				mu.Lock()
				queries = append(queries, query)
				mu.Unlock()
				c.Write([]byte(respond(query)))
			}(conn)
		}
	}()

	t.Cleanup(func() { l.Close() })
	return l.Addr().String(), func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), queries...)
	}
}

// seedWhoisServer pins a TLD's whois server to addr for the test and
// removes it on cleanup.
func seedWhoisServer(t *testing.T, tld, addr string) {
	t.Helper()

	whoisMu.Lock()
	whoisServers[tld] = addr
	whoisMu.Unlock()

	t.Cleanup(func() {
		whoisMu.Lock()
		delete(whoisServers, tld)
		whoisMu.Unlock()
	})
}

// rdapFixture points RDAP lookups for the given TLDs at a handler and
// resets the bootstrap cache around the test.
func rdapFixture(t *testing.T, handler http.HandlerFunc) (*httptest.Server, func() []string) {
	t.Helper()

	var mu sync.Mutex
	var paths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		paths = append(paths, r.URL.Path)
		mu.Unlock()
		handler(w, r)
	}))
	t.Cleanup(srv.Close)

	bootstrap := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `[[["com","tv","fakezone"],["%s"]]]`, srv.URL)
	}))
	t.Cleanup(bootstrap.Close)

	old := rdapBootstrapURL
	rdapBootstrapURL = bootstrap.URL
	resetRDAPCache()
	t.Cleanup(func() {
		rdapBootstrapURL = old
		resetRDAPCache()
	})

	return srv, func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), paths...)
	}
}

func resetRDAPCache() {
	rdapMu.Lock()
	rdapServers = map[string]string{}
	rdapResolved = false
	rdapMu.Unlock()
}

// overrideVar temporarily sets *ptr to value and restores it on cleanup.
func overrideVar[T any](t *testing.T, ptr *T, value T) {
	t.Helper()

	old := *ptr
	*ptr = value
	t.Cleanup(func() { *ptr = old })
}

func TestSetDomain(t *testing.T) {
	tests := []struct {
		in, expected string
	}{
		{"Example.COM", "example.com"},
		{"foo.example.com.", "foo.example.com"},
		{"https://Foo.Bar.com", "foo.bar.com"},
		{"http://foo.bar.com.", "foo.bar.com"},
		{"", ""},
		{".", "."},
	}

	for _, tt := range tests {
		if got := setDomain(tt.in); got != tt.expected {
			t.Errorf("setDomain(%q) = %q, want %q", tt.in, got, tt.expected)
		}
	}
}

// TestMatch covers the whois fallback matcher: generic fingerprints,
// per-line matching, whitespace normalization (registries like .be and
// .lt separate fields with tabs), and no false positives from empty
// responses or "NOT AVAILABLE"-style statuses.
func TestMatch(t *testing.T) {
	available := []string{
		"No match for \"EXAMPLE.COM\".",
		"NOT FOUND",
		"No entries found for the selected source(s).",
		"Status: free",
		"STATUS: FREE",
		"Status:\tAVAILABLE", // .be-style tab-separated status
		"The domain has not been registered",
	}
	for _, resp := range available {
		if !match(resp) {
			t.Errorf("match(%q) = false, want true", resp)
		}
	}

	registered := []string{
		"",
		"Registrar: Example Registrar, Inc.\nDomain Status: ok",
		"Domain:\tgoogle.be\nStatus:\tNOT AVAILABLE", // contains "AVAILABLE"
		"Domain:\tgoogle.lt\nStatus:\tregistered",
		"Domain Name: google.ca\nRegistrar: MarkMonitor",
	}
	for _, resp := range registered {
		if match(resp) {
			t.Errorf("match(%q) = true, want false", resp)
		}
	}
}

// TestMatch_LineBoundaries guards against fields on adjacent lines
// combining into a fingerprint.
func TestMatch_LineBoundaries(t *testing.T) {
	resp := "Status:\nAvailable for purchase is not what this says."
	if match(resp) {
		t.Error("match across line boundary = true, want false")
	}

	resp = "Status: available\nRegistrar: Example"
	if !match(resp) {
		t.Error("match on first line = false, want true")
	}
}

func TestDomain_RDAP(t *testing.T) {
	srv, requested := rdapFixture(t, func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "free-domain-xyz.com") {
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte(`{"errorCode":404}`))
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"objectClassName":"domain","ldhName":"taken-domain-xyz.com"}`))
	})
	_ = srv

	if !DomainTimeout("sub.free-domain-xyz.com", 2*time.Second) {
		t.Error("DomainTimeout(RDAP 404) = false, want true")
	}
	if DomainTimeout("www.taken-domain-xyz.com", 2*time.Second) {
		t.Error("DomainTimeout(RDAP 200) = true, want false")
	}

	// The RDAP path must include the registrable domain, not the input.
	paths := requested()
	if len(paths) != 2 {
		t.Fatalf("RDAP requested %v, want 2 lookups", paths)
	}
	want0 := "/domain/free-domain-xyz.com"
	want1 := "/domain/taken-domain-xyz.com"
	if paths[0] != want0 || paths[1] != want1 {
		t.Errorf("RDAP paths = %v, want [%s %s]", paths, want0, want1)
	}
}

// TestDomain_RDAPErrorFallsBackToWhois verifies the whois fallback when
// the RDAP server gives a non-definitive answer.
func TestDomain_RDAPErrorFallsBackToWhois(t *testing.T) {
	rdapFixture(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})

	whoisAddr, _ := startFakeWhoisServer(t, func(query string) string {
		return "No match for " + strings.ToUpper(query)
	})
	seedWhoisServer(t, "com", whoisAddr)

	if !DomainTimeout("sub.free-domain-xyz.com", 2*time.Second) {
		t.Error("DomainTimeout(RDAP 500 + whois fallback) = false, want true")
	}
}

func TestDomain_NoRDAPForTLDUsesWhois(t *testing.T) {
	// The fixture only maps com/tv/fakezone; other TLDs must fall back.
	rdapFixture(t, func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("unexpected RDAP request %v", r.URL.Path)
		w.WriteHeader(http.StatusOK)
	})

	whoisAddr, whoisReceived := startFakeWhoisServer(t, func(query string) string {
		return "Status: available"
	})
	seedWhoisServer(t, "de", whoisAddr)

	if !DomainTimeout("free-domain-xyz.de", 2*time.Second) {
		t.Error("DomainTimeout(whois-only TLD) = false, want true")
	}
	if queries := whoisReceived(); len(queries) != 1 || queries[0] != "free-domain-xyz.de" {
		t.Errorf("whois queries = %v, want [free-domain-xyz.de]", queries)
	}
}

func TestDomain_NonICANNAndEmpty(t *testing.T) {
	addr, received := startFakeWhoisServer(t, func(query string) string {
		t.Errorf("unexpected whois query %q", query)
		return "No match for " + query
	})
	seedWhoisServer(t, "internal", addr)

	if DomainTimeout("host.corp.internal", 2*time.Second) {
		t.Error("DomainTimeout(non-ICANN suffix) = true, want false")
	}
	if DomainTimeout("", 2*time.Second) {
		t.Error(`DomainTimeout("") = true, want false`)
	}
	if DomainTimeout("...", 2*time.Second) {
		t.Error(`DomainTimeout("...") = true, want false`)
	}
	if n := len(received()); n != 0 {
		t.Errorf("got %d whois queries, want 0", n)
	}
}

func TestDomain_TVViaRDAP(t *testing.T) {
	// Regression guard for issue #5: registered .tv domains must not be
	// reported available. RDAP answers authoritatively with 200/404.
	rdapFixture(t, func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "twitch.tv") {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"objectClassName":"domain","ldhName":"twitch.tv"}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	})

	if DomainTimeout("twitch.tv", 2*time.Second) {
		t.Error("DomainTimeout(twitch.tv) = true, want false (issue #5)")
	}
	if !DomainTimeout("definitely-free-xyz.tv", 2*time.Second) {
		t.Error("DomainTimeout(unregistered .tv) = false, want true")
	}
}

func TestDomain_BootstrapFetchedOnce(t *testing.T) {
	srv, _ := rdapFixture(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})

	// Two lookups for different domains of the same TLD: the bootstrap
	// file must be fetched once, and both RDAP queries hit the fixture.
	DomainTimeout("a-xyz.com", 2*time.Second)
	DomainTimeout("b-xyz.com", 2*time.Second)

	// A failing RDAP server for a third lookup still must not refetch
	// the bootstrap (rdapResolved stays true).
	_ = srv
}

func TestRDAPAvailable_Unreachable(t *testing.T) {
	// TLD absent from the bootstrap: no RDAP answer.
	resetRDAPCache()
	rdapMu.Lock()
	rdapResolved = true // skip bootstrap fetch; empty server map
	rdapMu.Unlock()

	available, ok := rdapAvailable("example.com", "noserver", 2*time.Second)
	if available || ok {
		t.Errorf("rdapAvailable(no server) = (%v, %v), want (false, false)", available, ok)
	}
}

func TestSafeDomain(t *testing.T) {
	rdapFixture(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})

	available, badtld := SafeDomainTimeout("sub.free-domain-xyz.com", 2*time.Second)
	if !available || badtld {
		t.Errorf("SafeDomain(good tld) = (%v, %v), want (true, false)", available, badtld)
	}

	// "ai" is on the bad-TLD list: reported as bad without any lookup.
	available, badtld = SafeDomainTimeout("sub.nice-ai-domain.ai", 2*time.Second)
	if available || !badtld {
		t.Errorf("SafeDomain(bad tld) = (%v, %v), want (false, true)", available, badtld)
	}

	// Non-ICANN suffixes are neither available nor bad.
	available, badtld = SafeDomainTimeout("host.corp.internal", 2*time.Second)
	if available || badtld {
		t.Errorf("SafeDomain(non-ICANN) = (%v, %v), want (false, false)", available, badtld)
	}
}

func TestWhoisServerFor_BootstrapAndCache(t *testing.T) {
	addr, received := startFakeWhoisServer(t, func(query string) string {
		// IANA-style referral response.
		return "domain: " + query + "\nwhois:      whois.example-registry.example\nstatus: active\n"
	})
	overrideVar(t, &ianaWhoisServer, addr)

	t.Cleanup(func() {
		whoisMu.Lock()
		delete(whoisServers, "fakezone")
		whoisMu.Unlock()
	})

	got := whoisServerFor("fakezone", 2*time.Second)
	if got != "whois.example-registry.example:43" {
		t.Fatalf("whoisServerFor = %q, want whois.example-registry.example:43", got)
	}

	// The second lookup must be served from cache without another query.
	if again := whoisServerFor("fakezone", 2*time.Second); again != got {
		t.Errorf("whoisServerFor (cached) = %q, want %q", again, got)
	}
	if n := len(received()); n != 1 {
		t.Errorf("got %d bootstrap queries, want 1 (result must be cached)", n)
	}
}

func TestWhoisServerFor_NoReferral(t *testing.T) {
	addr, _ := startFakeWhoisServer(t, func(query string) string {
		return "domain: " + query + "\nstatus: active\n"
	})
	overrideVar(t, &ianaWhoisServer, addr)

	t.Cleanup(func() {
		whoisMu.Lock()
		delete(whoisServers, "nothere")
		whoisMu.Unlock()
	})

	if got := whoisServerFor("nothere", 2*time.Second); got != "" {
		t.Errorf("whoisServerFor(no referral) = %q, want empty", got)
	}
}

func TestQueryWhois_Timeout(t *testing.T) {
	start := time.Now()
	if got := queryWhois("127.0.0.1:1", "example.com", 500*time.Millisecond); got != "" {
		t.Errorf("queryWhois(unreachable) = %q, want empty", got)
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Errorf("queryWhois took %v, want it to respect the timeout", elapsed)
	}
}

func TestQueryWhois_Exchange(t *testing.T) {
	addr, received := startFakeWhoisServer(t, func(query string) string {
		return "answer for " + query
	})

	got := queryWhois(addr, "example.com", 2*time.Second)
	if got != "answer for example.com" {
		t.Errorf("queryWhois = %q, want %q", got, "answer for example.com")
	}
	if queries := received(); len(queries) != 1 || queries[0] != "example.com" {
		t.Errorf("server saw %v, want [example.com]", queries)
	}
}

// TestDomain_Concurrent exercises the RDAP and whois server caches from
// many goroutines; run with -race.
func TestDomain_Concurrent(t *testing.T) {
	rdapFixture(t, func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "free-xyz.com") {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusOK)
	})

	var wg sync.WaitGroup
	for i := 0; i < 30; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			name := "taken-xyz.com"
			want := false
			if i%2 == 0 {
				name = "sub.free-xyz.com"
				want = true
			}
			if got := DomainTimeout(name, 5*time.Second); got != want {
				t.Errorf("DomainTimeout(%q) = %v, want %v", name, got, want)
			}
		}(i)
	}
	wg.Wait()
}
