<p align="center"><img src="https://raw.githubusercontent.com/go-newsgroups/brand/main/social/go-newsgroups.png" alt="go-newsgroups/nntp" width="720"></p>

# nntp

[![CI](https://github.com/go-newsgroups/nntp/actions/workflows/ci.yml/badge.svg)](https://github.com/go-newsgroups/nntp/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/go-newsgroups/nntp.svg)](https://pkg.go.dev/github.com/go-newsgroups/nntp)
[![License: BSD-3-Clause](https://img.shields.io/badge/License-BSD--3--Clause-blue.svg)](LICENSE)

A dependency-free, pure-Go **NNTP (Usenet) read client** following
[RFC 3977](https://www.rfc-editor.org/rfc/rfc3977). It uses only the Go standard
library (`net`, `net/textproto`, `crypto/tls`, ...), builds with `CGO_ENABLED=0`,
and pulls in **zero third-party dependencies**.

Supported operations: connect (plaintext or implicit TLS), `AUTHINFO`
authentication, `CAPABILITIES` negotiation, `MODE READER`, `GROUP` selection,
`OVER` overview retrieval (with automatic `XOVER` fallback), `ARTICLE` fetching,
and `LIST ACTIVE` newsgroup enumeration.

### Legacy and modern servers

The client works against both ancient NNRP servers that predate
[RFC 3977](https://www.rfc-editor.org/rfc/rfc3977) and modern servers such as
INN. `CAPABILITIES` is negotiated lazily and cached (and refreshed after
`AUTHINFO`, since a server may advertise different capabilities once
authenticated). A server that rejects `CAPABILITIES` is driven in *legacy mode*
rather than treated as an error, and `Over` transparently falls back from `OVER`
to the legacy `XOVER` command when the former is unknown.

```go
caps, _ := c.Capabilities()        // raw advertised capability lines (empty on legacy servers)
if c.Legacy() { /* pre-RFC-3977 server */ }
if c.HasCapability("OVER") { /* modern overview support */ }
_ = c.ModeReader()                 // enable reader commands where required (safe no-op elsewhere)
```

## Install

```sh
go get github.com/go-newsgroups/nntp
```

Requires Go 1.26.4 or newer.

## Usage

```go
package main

import (
	"context"
	"fmt"
	"log"

	"github.com/go-newsgroups/nntp"
)

func main() {
	ctx := context.Background()

	// Dial plaintext (port 119) — use nntp.DialTLS for implicit TLS (port 563).
	c, err := nntp.Dial(ctx, "news.example.org")
	if err != nil {
		log.Fatal(err)
	}
	defer c.Close()

	// Optional authentication.
	if err := c.Authenticate("user", "pass"); err != nil {
		log.Fatal(err)
	}

	// Select a group.
	g, err := c.Group("comp.lang.go")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%s: %d articles (%d-%d)\n", g.Name, g.Count, g.Low, g.High)

	// Read the overview for the last 10 articles.
	over, err := c.Over(g.High-9, g.High)
	if err != nil {
		log.Fatal(err)
	}
	for _, o := range over {
		fmt.Printf("#%d  %s  (%s)\n", o.ArticleNum, o.Subject, o.From)
	}
}
```

## API

| Method | NNTP command | Purpose |
| ------ | ------------ | ------- |
| `Dial` / `DialTLS` | — | Connect (plaintext / implicit TLS) and read the greeting |
| `Authenticate` | `AUTHINFO USER`/`PASS` | Authenticate (invalidates the cached capability set) |
| `Capabilities` | `CAPABILITIES` | Negotiate and return advertised capabilities (empty on legacy servers) |
| `HasCapability` | — | Case-insensitive check against the negotiated capability set |
| `Legacy` | — | Report whether the server predates `CAPABILITIES` (RFC 3977) |
| `ModeReader` | `MODE READER` | Switch to reader mode (tolerant no-op where unsupported) |
| `Group` | `GROUP` | Select a newsgroup |
| `Over` | `OVER` (→ `XOVER`) | Fetch article header summaries for a range, with legacy fallback |
| `Article` | `ARTICLE` | Fetch a full article by message-id or number |
| `List` | `LIST ACTIVE` | Enumerate newsgroups (optional wildmat filter) |
| `Close` | `QUIT` | Close the connection |

## License

BSD-3-Clause. See [LICENSE](LICENSE). Copyright the go-newsgroups/nntp authors.
