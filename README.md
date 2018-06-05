# Is 'domain.x' Available?

[![Build Status](https://api.travis-ci.org/haccer/available.svg?branch=master)](https://travis-ci.org/haccer/available)[![Go Report Card](https://goreportcard.com/badge/github.com/haccer/available)](https://goreportcard.com/report/github.com/haccer/available) [![GitHub license](https://img.shields.io/github/license/haccer/available.svg)](https://github.com/haccer/available/blob/master/LICENSE)

My cheap way of checking whether a domain exists or not (powered by whois).

### Usage
```Go
Domain(available bool, badtld bool)
```

### Example

```Go
package main

import (
        "fmt"
        "github.com/haccer/available"
)

func main() {
        domain := "dreamdomain.io"

        available, badtld := available.Domain(domain)

        if badtld {
                fmt.Println("[-] BadTLD. No Whois server to check :(")
        }

        if available {
                fmt.Println("[+] Success!")
        }
}
```
