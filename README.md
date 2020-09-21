# Is 'domain.x' Available?
[![Build Status](https://api.travis-ci.org/haccer/available.svg?branch=master)](https://travis-ci.org/haccer/available) 
[![Go Report Card](https://goreportcard.com/badge/github.com/haccer/available)](https://goreportcard.com/report/github.com/haccer/available) 
[![GoDoc](https://godoc.org/github.com/haccer/available?status.svg)](http://godoc.org/github.com/haccer/available) 
[![GitHub license](https://img.shields.io/github/license/haccer/available.svg)](https://github.com/haccer/available/blob/master/LICENSE) 
> IN WHOIS WE TRUST

My cheap way of checking whether a domain is available to be purchased or not (powered by [whois](https://github.com/domainr/whois)).

#### Disclaimer
This package _might not_ be able to check the available for _every_ possible domain TLD, since `whois` does not work with some TLDs. In the future, I might include options to call different APIs (Gandi API, Domainr, etc.).

### Example

```Go
package main

import (
        "fmt"
        "github.com/haccer/available"
)

func main() {
        domain := "dreamdomain.io"

        available, err := available.Domain(domain)
        if err != nil {
                panic(err)
        }

        if available {
                fmt.Println("[+] Success!")
        }
}
```
