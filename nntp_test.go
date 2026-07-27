package nntp

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"
)

// scriptServer is a minimal in-process NNTP server for tests. It writes a
// greeting, then for every command line received invokes handler, writes the
// returned reply, and closes the connection when handler asks it to.
type scriptServer struct {
	greeting string
	useTLS   bool
	handler  func(line string) (reply string, closeAfter bool)
}

// genCert produces a self-signed ECDSA certificate valid for 127.0.0.1.
func genCert(t *testing.T) tls.Certificate {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "127.0.0.1"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:     []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("createcert: %v", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv}
}

// start launches the server and returns its address plus a client tls.Config
// (nil for plaintext).
func (s scriptServer) start(t *testing.T) (string, *tls.Config) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	var clientCfg *tls.Config
	var serverCfg *tls.Config
	if s.useTLS {
		cert := genCert(t)
		serverCfg = &tls.Config{Certificates: []tls.Certificate{cert}}
		clientCfg = &tls.Config{InsecureSkipVerify: true}
	}

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		if s.useTLS {
			tc := tls.Server(conn, serverCfg)
			if err := tc.Handshake(); err != nil {
				return
			}
			conn = tc
		}
		r := bufio.NewReader(conn)
		w := bufio.NewWriter(conn)
		_, _ = w.WriteString(s.greeting)
		_ = w.Flush()
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				return
			}
			reply, closeAfter := s.handler(strings.TrimRight(line, "\r\n"))
			_, _ = w.WriteString(reply)
			_ = w.Flush()
			if closeAfter {
				return
			}
		}
	}()
	return ln.Addr().String(), clientCfg
}

// dial connects a client to a freshly started plaintext scriptServer.
func dial(t *testing.T, greeting string, handler func(string) (string, bool)) *Conn {
	t.Helper()
	addr, _ := scriptServer{greeting: greeting, handler: handler}.start(t)
	c, err := Dial(context.Background(), addr)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

const okGreeting = "200 news.example ready\r\n"

func TestEnsurePort(t *testing.T) {
	if got := ensurePort("host", "119"); got != "host:119" {
		t.Errorf("ensurePort(no port) = %q", got)
	}
	if got := ensurePort("host:9999", "119"); got != "host:9999" {
		t.Errorf("ensurePort(with port) = %q", got)
	}
}

func TestDialContextCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Dial(ctx, "127.0.0.1:119"); err == nil {
		t.Fatal("Dial: expected error on cancelled context")
	}
	if _, err := DialTLS(ctx, "127.0.0.1:563", nil); err == nil {
		t.Fatal("DialTLS: expected error on cancelled context")
	}
}

func TestDialBadGreeting(t *testing.T) {
	addr, _ := scriptServer{
		greeting: "400 service temporarily unavailable\r\n",
		handler:  func(string) (string, bool) { return "", true },
	}.start(t)
	if _, err := Dial(context.Background(), addr); err == nil {
		t.Fatal("expected error on bad greeting")
	}
}

func TestDialTLS(t *testing.T) {
	handler := func(line string) (string, bool) {
		if line == "QUIT" {
			return "205 bye\r\n", true
		}
		return "500 unknown\r\n", false
	}
	addr, cfg := scriptServer{greeting: okGreeting, useTLS: true, handler: handler}.start(t)
	c, err := DialTLS(context.Background(), addr, cfg)
	if err != nil {
		t.Fatalf("DialTLS: %v", err)
	}
	if err := c.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

func TestSession(t *testing.T) {
	handler := func(line string) (string, bool) {
		switch {
		case line == "GROUP misc.test":
			return "211 42 1 100 misc.test\r\n", false
		case line == "OVER 1-2":
			// good date, bad date, and a malformed short line (skipped).
			return "224 overview follows\r\n" +
				"1\tHello\tAlice <a@x>\tMon, 02 Jan 2006 15:04:05 -0700\t<1@x>\t\t512\t7\r\n" +
				"2\tWorld\tBob <b@x>\tnot-a-date\t<2@x>\t<1@x>\t256\t3\r\n" +
				"short\tline\r\n" +
				".\r\n", false
		case line == "ARTICLE <1@x>":
			return "220 0 <1@x> article follows\r\n" +
				"Subject: Hello\r\n" +
				"From: Alice <a@x>\r\n" +
				"X-Bad-Header-No-Colon\r\n" +
				"X-Multi: one\r\n" +
				"X-Multi: two\r\n" +
				"\r\n" +
				"Line one\r\n" +
				"Line two\r\n" +
				".\r\n", false
		case line == "LIST ACTIVE":
			return "215 list follows\r\n" +
				"misc.test 100 1 y\r\n" +
				"comp.lang.go 500 1 n\r\n" +
				"malformed line\r\n" +
				".\r\n", false
		case line == "LIST ACTIVE comp.*":
			return "215 list follows\r\n" +
				"comp.lang.go 500 1 n\r\n" +
				".\r\n", false
		case line == "QUIT":
			return "205 bye\r\n", true
		}
		return "500 unknown command\r\n", false
	}
	c := dial(t, okGreeting, handler)

	g, err := c.Group("misc.test")
	if err != nil {
		t.Fatalf("Group: %v", err)
	}
	if g.Name != "misc.test" || g.Count != 42 || g.Low != 1 || g.High != 100 {
		t.Errorf("Group = %+v", g)
	}

	ov, err := c.Over(1, 2)
	if err != nil {
		t.Fatalf("Over: %v", err)
	}
	if len(ov) != 2 {
		t.Fatalf("Over len = %d, want 2", len(ov))
	}
	if ov[0].ArticleNum != 1 || ov[0].Subject != "Hello" || ov[0].MessageID != "<1@x>" ||
		ov[0].Bytes != 512 || ov[0].Lines != 7 || ov[0].Date.IsZero() {
		t.Errorf("Over[0] = %+v", ov[0])
	}
	if !ov[1].Date.IsZero() {
		t.Errorf("Over[1].Date should be zero for bad date, got %v", ov[1].Date)
	}

	art, err := c.Article("<1@x>")
	if err != nil {
		t.Fatalf("Article: %v", err)
	}
	if got := art.Headers["Subject"]; len(got) != 1 || got[0] != "Hello" {
		t.Errorf("Article Subject = %v", got)
	}
	if got := art.Headers["X-Multi"]; len(got) != 2 || got[0] != "one" || got[1] != "two" {
		t.Errorf("Article X-Multi = %v", got)
	}
	if art.Body != "Line one\nLine two" {
		t.Errorf("Article Body = %q", art.Body)
	}

	list, err := c.List("")
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(list) != 2 || list[0].Name != "misc.test" || list[0].High != 100 ||
		list[0].Low != 1 || list[0].Status != "y" {
		t.Errorf("List = %+v", list)
	}

	wl, err := c.List("comp.*")
	if err != nil {
		t.Fatalf("List(wildmat): %v", err)
	}
	if len(wl) != 1 || wl[0].Name != "comp.lang.go" {
		t.Errorf("List(wildmat) = %+v", wl)
	}
}

func TestGroupErrors(t *testing.T) {
	cases := []struct {
		name  string
		reply string
	}{
		{"badcode", "411 no such group\r\n"},
		{"shortfields", "211 42 1\r\n"},
		{"badcount", "211 x 1 100 misc.test\r\n"},
		{"badlow", "211 42 x 100 misc.test\r\n"},
		{"badhigh", "211 42 1 x misc.test\r\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := dial(t, okGreeting, func(line string) (string, bool) {
				if line == "QUIT" {
					return "205 bye\r\n", true
				}
				return tc.reply, false
			})
			if _, err := c.Group("misc.test"); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestOverErrors(t *testing.T) {
	t.Run("badcode", func(t *testing.T) {
		c := dial(t, okGreeting, func(line string) (string, bool) {
			if line == "QUIT" {
				return "205 bye\r\n", true
			}
			return "423 no such range\r\n", false
		})
		if _, err := c.Over(1, 2); err == nil {
			t.Fatal("expected error")
		}
	})
	t.Run("truncated", func(t *testing.T) {
		// Send the status line then close before the dot terminator.
		c := dial(t, okGreeting, func(line string) (string, bool) {
			return "224 overview follows\r\n1\tHi\r\n", true
		})
		if _, err := c.Over(1, 2); err == nil {
			t.Fatal("expected error on truncated block")
		}
	})
}

func TestArticleErrors(t *testing.T) {
	t.Run("badcode", func(t *testing.T) {
		c := dial(t, okGreeting, func(line string) (string, bool) {
			if line == "QUIT" {
				return "205 bye\r\n", true
			}
			return "430 no such article\r\n", false
		})
		if _, err := c.Article("<x@x>"); err == nil {
			t.Fatal("expected error")
		}
	})
	t.Run("truncated", func(t *testing.T) {
		c := dial(t, okGreeting, func(line string) (string, bool) {
			return "220 0 <x@x>\r\nSubject: Hi\r\n", true
		})
		if _, err := c.Article("<x@x>"); err == nil {
			t.Fatal("expected error on truncated block")
		}
	})
}

func TestListErrors(t *testing.T) {
	t.Run("badcode", func(t *testing.T) {
		c := dial(t, okGreeting, func(line string) (string, bool) {
			if line == "QUIT" {
				return "205 bye\r\n", true
			}
			return "503 unavailable\r\n", false
		})
		if _, err := c.List(""); err == nil {
			t.Fatal("expected error")
		}
	})
	t.Run("truncated", func(t *testing.T) {
		c := dial(t, okGreeting, func(line string) (string, bool) {
			return "215 list follows\r\nmisc.test 1 1 y\r\n", true
		})
		if _, err := c.List(""); err == nil {
			t.Fatal("expected error on truncated block")
		}
	})
}

func TestAuthenticate(t *testing.T) {
	t.Run("user-then-pass", func(t *testing.T) {
		c := dial(t, okGreeting, func(line string) (string, bool) {
			switch {
			case strings.HasPrefix(line, "AUTHINFO USER"):
				return "381 password required\r\n", false
			case strings.HasPrefix(line, "AUTHINFO PASS"):
				return "281 authenticated\r\n", false
			case line == "QUIT":
				return "205 bye\r\n", true
			}
			return "500 unknown\r\n", false
		})
		if err := c.Authenticate("bob", "secret"); err != nil {
			t.Fatalf("Authenticate: %v", err)
		}
	})

	t.Run("user-accepted", func(t *testing.T) {
		c := dial(t, okGreeting, func(line string) (string, bool) {
			if strings.HasPrefix(line, "AUTHINFO USER") {
				return "281 authenticated\r\n", false
			}
			if line == "QUIT" {
				return "205 bye\r\n", true
			}
			return "500 unknown\r\n", false
		})
		if err := c.Authenticate("bob", "secret"); err != nil {
			t.Fatalf("Authenticate: %v", err)
		}
	})

	t.Run("user-rejected", func(t *testing.T) {
		c := dial(t, okGreeting, func(line string) (string, bool) {
			if strings.HasPrefix(line, "AUTHINFO USER") {
				return "482 command unavailable\r\n", false
			}
			if line == "QUIT" {
				return "205 bye\r\n", true
			}
			return "500 unknown\r\n", false
		})
		if err := c.Authenticate("bob", "secret"); err == nil {
			t.Fatal("expected error on rejected user")
		}
	})

	t.Run("pass-rejected", func(t *testing.T) {
		c := dial(t, okGreeting, func(line string) (string, bool) {
			switch {
			case strings.HasPrefix(line, "AUTHINFO USER"):
				return "381 password required\r\n", false
			case strings.HasPrefix(line, "AUTHINFO PASS"):
				return "481 authentication failed\r\n", false
			case line == "QUIT":
				return "205 bye\r\n", true
			}
			return "500 unknown\r\n", false
		})
		if err := c.Authenticate("bob", "bad"); err == nil {
			t.Fatal("expected error on rejected password")
		}
	})

	t.Run("user-read-error", func(t *testing.T) {
		c := dial(t, okGreeting, func(line string) (string, bool) {
			return "", true // close without replying
		})
		if err := c.Authenticate("bob", "secret"); err == nil {
			t.Fatal("expected read error after USER")
		}
	})

	t.Run("pass-read-error", func(t *testing.T) {
		c := dial(t, okGreeting, func(line string) (string, bool) {
			if strings.HasPrefix(line, "AUTHINFO USER") {
				return "381 password required\r\n", false
			}
			return "", true // close on PASS
		})
		if err := c.Authenticate("bob", "secret"); err == nil {
			t.Fatal("expected read error after PASS")
		}
	})
}

// modernCaps is a representative INN CAPABILITIES reply.
const modernCaps = "101 Capability list:\r\n" +
	"VERSION 2\r\n" +
	"READER\r\n" +
	"OVER\r\n" +
	"HDR\r\n" +
	"POST\r\n" +
	"AUTHINFO USER\r\n" +
	"COMPRESS DEFLATE\r\n" +
	"LIST ACTIVE NEWSGROUPS\r\n" +
	"\r\n" + // blank line: must be skipped, not indexed
	".\r\n"

func TestCapabilitiesModern(t *testing.T) {
	c := dial(t, okGreeting, func(line string) (string, bool) {
		switch line {
		case "CAPABILITIES":
			return modernCaps, false
		case "QUIT":
			return "205 bye\r\n", true
		}
		return "500 unknown\r\n", false
	})

	caps, err := c.Capabilities()
	if err != nil {
		t.Fatalf("Capabilities: %v", err)
	}
	// Raw lines are returned verbatim (the trailing blank line included); it is
	// only the capability set consulted by HasCapability that skips blanks.
	if len(caps) != 9 {
		t.Fatalf("Capabilities returned %d lines, want 9: %v", len(caps), caps)
	}
	if caps[0] != "VERSION 2" {
		t.Errorf("caps[0] = %q, want %q", caps[0], "VERSION 2")
	}
	if c.Legacy() {
		t.Error("Legacy() = true on modern server")
	}
	for _, name := range []string{"version", "READER", "over", "HDR", "post", "authinfo", "compress"} {
		if !c.HasCapability(name) {
			t.Errorf("HasCapability(%q) = false, want true", name)
		}
	}
	if c.HasCapability("STARTTLS") {
		t.Error("HasCapability(STARTTLS) = true, want false")
	}
}

func TestCapabilitiesLegacy(t *testing.T) {
	for _, code := range []string{"500", "501", "480"} {
		t.Run(code, func(t *testing.T) {
			c := dial(t, okGreeting, func(line string) (string, bool) {
				switch line {
				case "CAPABILITIES":
					return code + " What?\r\n", false
				case "QUIT":
					return "205 bye\r\n", true
				}
				return "500 unknown\r\n", false
			})
			caps, err := c.Capabilities()
			if err != nil {
				t.Fatalf("Capabilities: %v", err)
			}
			if caps == nil || len(caps) != 0 {
				t.Errorf("Capabilities = %v, want empty non-nil slice", caps)
			}
			if !c.Legacy() {
				t.Error("Legacy() = false, want true")
			}
			if c.HasCapability("OVER") {
				t.Error("HasCapability(OVER) = true in legacy mode")
			}
		})
	}
}

func TestCapabilitiesErrors(t *testing.T) {
	t.Run("read-error", func(t *testing.T) {
		// Close immediately: CAPABILITIES gets no status line at all.
		c := dial(t, okGreeting, func(string) (string, bool) { return "", true })
		if _, err := c.Capabilities(); err == nil {
			t.Fatal("expected read error")
		}
		// Lazy accessors swallow the error and report the safe default.
		if c.HasCapability("OVER") {
			t.Error("HasCapability = true after negotiation failure")
		}
		if c.Legacy() {
			t.Error("Legacy = true after negotiation failure")
		}
	})
	t.Run("truncated-block", func(t *testing.T) {
		// 101 status line then EOF before the dot terminator.
		c := dial(t, okGreeting, func(string) (string, bool) {
			return "101 caps follow\r\nVERSION 2\r\n", true
		})
		if _, err := c.Capabilities(); err == nil {
			t.Fatal("expected error on truncated block")
		}
	})
}

func TestNegotiateCached(t *testing.T) {
	var count int
	c := dial(t, okGreeting, func(line string) (string, bool) {
		switch line {
		case "CAPABILITIES":
			count++
			return modernCaps, false
		case "QUIT":
			return "205 bye\r\n", true
		}
		return "500 unknown\r\n", false
	})
	// Two lazy lookups must trigger exactly one CAPABILITIES exchange.
	if !c.HasCapability("OVER") || c.Legacy() {
		t.Fatal("unexpected negotiation result")
	}
	if count != 1 {
		t.Fatalf("CAPABILITIES sent %d times, want 1", count)
	}
}

func TestNegotiateAfterAuth(t *testing.T) {
	var count int
	c := dial(t, okGreeting, func(line string) (string, bool) {
		switch {
		case line == "CAPABILITIES":
			count++
			return modernCaps, false
		case strings.HasPrefix(line, "AUTHINFO USER"):
			return "281 authenticated\r\n", false
		case line == "QUIT":
			return "205 bye\r\n", true
		}
		return "500 unknown\r\n", false
	})
	if !c.HasCapability("OVER") {
		t.Fatal("HasCapability(OVER) = false before auth")
	}
	if err := c.Authenticate("bob", "secret"); err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	// Authentication invalidates the cache; the next lookup re-negotiates.
	if !c.HasCapability("READER") {
		t.Fatal("HasCapability(READER) = false after auth")
	}
	if count != 2 {
		t.Fatalf("CAPABILITIES sent %d times, want 2 (once per auth state)", count)
	}
}

func TestModeReader(t *testing.T) {
	cases := []struct {
		name    string
		reply   string
		wantErr bool
	}{
		{"posting-allowed", "200 reader mode, posting allowed\r\n", false},
		{"posting-prohibited", "201 reader mode, posting prohibited\r\n", false},
		{"not-implemented", "500 unknown command\r\n", false},
		{"not-implemented-501", "501 not supported\r\n", false},
		{"unexpected", "400 service discontinued\r\n", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := dial(t, okGreeting, func(line string) (string, bool) {
				if line == "QUIT" {
					return "205 bye\r\n", true
				}
				return tc.reply, false
			})
			err := c.ModeReader()
			if tc.wantErr != (err != nil) {
				t.Fatalf("ModeReader err = %v, wantErr = %v", err, tc.wantErr)
			}
		})
	}
	t.Run("read-error", func(t *testing.T) {
		c := dial(t, okGreeting, func(string) (string, bool) { return "", true })
		if err := c.ModeReader(); err == nil {
			t.Fatal("expected read error")
		}
	})
}

func TestCommandsAfterClose(t *testing.T) {
	// Closing the underlying connection makes every subsequent command's write
	// fail deterministically, exercising the Cmd write-error guards in the
	// shared helpers (a naive StartResponse on the failed id would otherwise
	// deadlock the textproto response pipeline).
	newDead := func() *Conn {
		c := dial(t, okGreeting, func(string) (string, bool) { return "500 x\r\n", false })
		c.conn.Close()
		return c
	}
	if err := newDead().ModeReader(); err == nil { // simpleCmd path
		t.Error("ModeReader: expected error after close")
	}
	if _, err := newDead().Over(1, 2); err == nil { // multiCmd path
		t.Error("Over: expected error after close")
	}
	if _, err := newDead().Capabilities(); err == nil {
		t.Error("Capabilities: expected error after close")
	}
	if err := newDead().Close(); err == nil { // QUIT write fails, still closes
		t.Error("Close: expected error after close")
	}
}

func TestOverXOVERFallback(t *testing.T) {
	t.Run("fallback-success", func(t *testing.T) {
		c := dial(t, okGreeting, func(line string) (string, bool) {
			switch {
			case strings.HasPrefix(line, "OVER"):
				return "500 unknown command\r\n", false
			case strings.HasPrefix(line, "XOVER"):
				return "224 overview follows\r\n" +
					"1\tHello\tAlice <a@x>\tMon, 02 Jan 2006 15:04:05 -0700\t<1@x>\t\t512\t7\r\n" +
					".\r\n", false
			case line == "QUIT":
				return "205 bye\r\n", true
			}
			return "500 unknown\r\n", false
		})
		ov, err := c.Over(1, 2)
		if err != nil {
			t.Fatalf("Over: %v", err)
		}
		if len(ov) != 1 || ov[0].Subject != "Hello" {
			t.Fatalf("Over = %+v", ov)
		}
	})
	t.Run("fallback-also-fails", func(t *testing.T) {
		c := dial(t, okGreeting, func(line string) (string, bool) {
			if line == "QUIT" {
				return "205 bye\r\n", true
			}
			// Both OVER and XOVER are rejected.
			return "501 command syntax error\r\n", false
		})
		if _, err := c.Over(1, 2); err == nil {
			t.Fatal("expected error when XOVER fallback also fails")
		}
	})
}

func TestParseDateTwoDigitYear(t *testing.T) {
	// Legacy RFC 822 2-digit-year date used by Free's alt.binaries.* servers.
	got := parseDate("Tue, 07 Jul 26 11:13:37 UTC")
	if got.IsZero() {
		t.Fatal("2-digit-year date parsed to the zero time")
	}
	if got.Year() != 2026 || got.Month() != 7 || got.Day() != 7 {
		t.Fatalf("parsed = %v, want 2026-07-07", got.Format("2006-01-02"))
	}
	// A genuinely malformed date still yields the zero time.
	if !parseDate("not a date").IsZero() {
		t.Fatal("garbage date should be zero")
	}
}
