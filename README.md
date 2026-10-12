# Is 'domain.x' Available?
[![CI](https://github.com/haccer/available/actions/workflows/ci.yml/badge.svg)](https://github.com/haccer/available/actions/workflows/ci.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/haccer/available)](https://goreportcard.com/report/github.com/haccer/available)
[![GoDoc](https://godoc.org/github.com/haccer/available?status.svg)](http://godoc.org/github.com/haccer/available)
[![GitHub license](https://img.shields.io/github/license/haccer/available.svg)](https://github.com/haccer/available/blob/master/LICENSE)
> IN RDAP WE TRUST

My cheap way of checking whether a domain is available to be purchased or not.

Availability is checked with **RDAP** first ([RFC 9083](https://datatracker.ietf.org/doc/html/rfc9083)): the answer is carried by the HTTP status itself — `404` means the domain is not registered, `200` means it is. RDAP servers are discovered from the [IANA bootstrap file](https://data.iana.org/rdap/dns.json) and cached per TLD, so there is no per-TLD configuration to maintain and no registry response text to fingerprint. TLDs without RDAP fall back to a small whois client ([RFC 3912](https://datatracker.ietf.org/doc/html/rfc3912)) that discovers authoritative servers via IANA referral and matches a short list of generic "available" responses.

The only dependency is `golang.org/x/net` (for public suffix data).

#### Disclaimer
This package _might not_ be able to check the availability of _every_ possible domain TLD. Always double-check results manually before acting on them.

### Usage

```Go
package main

import (
        "fmt"
        "time"

        "github.com/haccer/available"
)

func main() {
        // Domain uses a 10s timeout.
        if available.Domain("dreamdomain.io") {
                fmt.Println("[+] Success!")
        }

        // ...or supply your own timeout.
        available.DomainTimeout("dreamdomain.io", 5*time.Second)

        // SafeDomain also reports whether the TLD has no usable whois/RDAP
        // server ("bad" TLD), so you can skip or flag it.
        avail, badTLD := available.SafeDomain("dreamdomain.io")
        fmt.Println(avail, badTLD)
}
```

All functions are safe for concurrent use: subdomains are reduced to their registrable domain (eTLD+1) first, and the bootstrap data and whois servers are resolved once per TLD and cached.

### Tests

The test suite runs entirely offline against local RDAP and whois fixtures:

```
go test -race ./...
```
