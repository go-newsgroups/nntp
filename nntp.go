// Package nntp implements a dependency-free NNTP (Usenet) read client
// following RFC 3977. It uses only the Go standard library (CGO_ENABLED=0)
// and speaks the command/response protocol over net/textproto.
//
// The client is intended for reading: connecting, authenticating, selecting
// groups, listing overviews, fetching articles and enumerating newsgroups.
package nntp

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/textproto"
	"strconv"
	"strings"
	"time"

	"github.com/go-datetime/dates"
)

// Conn is a connection to an NNTP server. It wraps a *textproto.Conn layered
// over the underlying net.Conn. A Conn is not safe for concurrent use.
//
// Conn transparently bridges legacy NNRP servers (which predate RFC 3977 and
// reject CAPABILITIES) and modern servers (INN and the like). Capability
// negotiation is performed lazily and cached; see Capabilities, HasCapability
// and Legacy.
type Conn struct {
	conn net.Conn
	text *textproto.Conn

	// caps holds the upper-cased first token of every advertised capability
	// line (e.g. "OVER", "AUTHINFO", "COMPRESS"). It is nil in legacy mode.
	caps map[string]bool
	// legacy is true once negotiation found the server does not implement
	// CAPABILITIES (an RFC 3977 predecessor such as classic NNRP).
	legacy bool
	// negotiated records whether capability negotiation has run since the
	// last connect or AUTHINFO exchange, so it happens at most once per state.
	negotiated bool
}

// codeOf extracts the NNTP status code carried by a *textproto.Error, or 0 for
// any other (e.g. network) error.
func codeOf(err error) int {
	var te *textproto.Error
	if errors.As(err, &te) {
		return te.Code
	}
	return 0
}

// ensurePort returns addr unchanged if it already carries a port, otherwise it
// appends the given default port.
func ensurePort(addr, def string) string {
	if _, _, err := net.SplitHostPort(addr); err != nil {
		return net.JoinHostPort(addr, def)
	}
	return addr
}

// Dial connects (plaintext) to addr ("host:port"); if no port is present the
// default NNTP port 119 is used. The greeting is read and validated.
func Dial(ctx context.Context, addr string) (*Conn, error) {
	var d net.Dialer
	nc, err := d.DialContext(ctx, "tcp", ensurePort(addr, "119"))
	if err != nil {
		return nil, err
	}
	return newConn(nc)
}

// DialTLS connects with implicit TLS to addr; if no port is present the default
// NNTPS port 563 is used. tlsConfig may be nil, in which case the platform
// defaults are used.
func DialTLS(ctx context.Context, addr string, tlsConfig *tls.Config) (*Conn, error) {
	d := tls.Dialer{Config: tlsConfig}
	nc, err := d.DialContext(ctx, "tcp", ensurePort(addr, "563"))
	if err != nil {
		return nil, err
	}
	return newConn(nc)
}

// newConn wraps an established connection and consumes the server greeting,
// which must be 200 (posting allowed) or 201 (no posting).
func newConn(nc net.Conn) (*Conn, error) {
	c := &Conn{conn: nc, text: textproto.NewConn(nc)}
	if _, _, err := c.text.ReadCodeLine(20); err != nil {
		c.text.Close()
		return nil, err
	}
	return c, nil
}

// simpleCmd sends a single command and reads a single status line, returning
// its code and message. expect follows textproto.ReadCodeLine semantics.
func (c *Conn) simpleCmd(expect int, format string, args ...any) (int, string, error) {
	id, err := c.text.Cmd(format, args...)
	if err != nil {
		return 0, "", err
	}
	c.text.StartResponse(id)
	defer c.text.EndResponse(id)
	return c.text.ReadCodeLine(expect)
}

// multiCmd sends a command whose response is a status line followed by a
// dot-terminated multiline block, and returns the block's lines.
func (c *Conn) multiCmd(expect int, format string, args ...any) ([]string, error) {
	id, err := c.text.Cmd(format, args...)
	if err != nil {
		return nil, err
	}
	c.text.StartResponse(id)
	defer c.text.EndResponse(id)
	if _, _, err := c.text.ReadCodeLine(expect); err != nil {
		return nil, err
	}
	return c.text.ReadDotLines()
}

// Authenticate performs AUTHINFO USER/PASS authentication.
func (c *Conn) Authenticate(user, pass string) error {
	code, msg, err := c.simpleCmd(0, "AUTHINFO USER %s", user)
	if err != nil {
		return err
	}
	switch code {
	case 281: // accepted without password
		c.negotiated = false // capabilities may change post-auth (RFC 3977 §5.3)
		return nil
	case 381: // password required, continue
	default:
		return fmt.Errorf("nntp: AUTHINFO USER unexpected code %d: %s", code, msg)
	}
	code, msg, err = c.simpleCmd(0, "AUTHINFO PASS %s", pass)
	if err != nil {
		return err
	}
	if code == 281 {
		c.negotiated = false // capabilities may change post-auth (RFC 3977 §5.3)
		return nil
	}
	return fmt.Errorf("nntp: AUTHINFO PASS rejected code %d: %s", code, msg)
}

// Capabilities issues the CAPABILITIES command (RFC 3977 §5.2) and returns the
// raw capability lines advertised by the server (for example "VERSION 2",
// "AUTHINFO USER", "COMPRESS DEFLATE").
//
// Legacy servers that predate RFC 3977 reject the command with 500, 501 or 480
// (authentication required first). That is not treated as an error: Capabilities
// then returns an empty slice with a nil error and the connection enters legacy
// mode (see Legacy). The negotiated set is cached and reused by HasCapability
// and Legacy; it is refreshed after a successful AUTHINFO exchange, since a
// server may advertise different capabilities once the client is authenticated.
func (c *Conn) Capabilities() ([]string, error) {
	id, err := c.text.Cmd("CAPABILITIES")
	if err != nil {
		return nil, err
	}
	c.text.StartResponse(id)
	defer c.text.EndResponse(id)
	if _, _, err := c.text.ReadCodeLine(101); err != nil {
		switch codeOf(err) {
		case 500, 501, 480: // unknown/unsupported command, or auth-first: legacy
			c.caps = nil
			c.legacy = true
			c.negotiated = true
			return []string{}, nil
		}
		return nil, err
	}
	lines, err := c.text.ReadDotLines()
	if err != nil {
		return nil, err
	}
	c.caps = make(map[string]bool, len(lines))
	for _, l := range lines {
		f := strings.Fields(l)
		if len(f) == 0 {
			continue
		}
		c.caps[strings.ToUpper(f[0])] = true
	}
	c.legacy = false
	c.negotiated = true
	return lines, nil
}

// TODO(compress): a server advertising COMPRESS DEFLATE (detectable via
// HasCapability("COMPRESS")) supports RFC 8054 compressed streaming. Actually
// negotiating COMPRESS DEFLATE and wrapping the transport in a flate reader/
// writer is a larger change left as a future enhancement; only detection is
// provided here.

// negotiate runs capability negotiation once and caches the result. Subsequent
// calls are no-ops until the connection state changes (e.g. after AUTHINFO).
func (c *Conn) negotiate() error {
	if c.negotiated {
		return nil
	}
	_, err := c.Capabilities()
	return err
}

// HasCapability reports whether the server advertised the named capability
// (matched case-insensitively against the first token of each capability line,
// e.g. "OVER", "HDR", "READER", "POST", "AUTHINFO", "COMPRESS"). It negotiates
// lazily on first use and returns false in legacy mode or if negotiation fails.
func (c *Conn) HasCapability(name string) bool {
	if c.negotiate() != nil {
		return false
	}
	return c.caps[strings.ToUpper(name)]
}

// Legacy reports whether the server does not implement CAPABILITIES (RFC 3977)
// and is therefore driven in legacy NNRP mode. It negotiates lazily on first
// use.
func (c *Conn) Legacy() bool {
	_ = c.negotiate()
	return c.legacy
}

// ModeReader issues MODE READER (RFC 3977 §5.3), which some servers require
// before they enable reader commands. A 200 (posting allowed) or 201 (posting
// prohibited) reply is a success. Servers that do not implement the command
// answer 500/501; that is tolerated and treated as a no-op success, so calling
// ModeReader is always safe, including on servers that already greet in reader
// mode. Dial does not send MODE READER automatically, to preserve the exact
// on-the-wire behaviour existing callers rely on; call it explicitly when
// targeting a server that gates reader commands behind it.
func (c *Conn) ModeReader() error {
	code, msg, err := c.simpleCmd(0, "MODE READER")
	if err != nil {
		return err
	}
	switch code {
	case 200, 201: // reader mode active (posting allowed / prohibited)
		return nil
	case 500, 501: // not implemented: treat as a no-op success
		return nil
	default:
		return fmt.Errorf("nntp: MODE READER unexpected code %d: %s", code, msg)
	}
}

// Group is the result of selecting a newsgroup with GROUP.
type Group struct {
	Name  string
	Count int
	Low   int
	High  int
}

// Group selects the named newsgroup and returns its estimated article count and
// low/high water marks, parsed from a "211 count low high name" response.
func (c *Conn) Group(name string) (*Group, error) {
	_, msg, err := c.simpleCmd(211, "GROUP %s", name)
	if err != nil {
		return nil, err
	}
	f := strings.Fields(msg)
	if len(f) < 4 {
		return nil, fmt.Errorf("nntp: malformed GROUP response: %q", msg)
	}
	count, err := strconv.Atoi(f[0])
	if err != nil {
		return nil, fmt.Errorf("nntp: GROUP count: %w", err)
	}
	low, err := strconv.Atoi(f[1])
	if err != nil {
		return nil, fmt.Errorf("nntp: GROUP low: %w", err)
	}
	high, err := strconv.Atoi(f[2])
	if err != nil {
		return nil, fmt.Errorf("nntp: GROUP high: %w", err)
	}
	return &Group{Name: f[3], Count: count, Low: low, High: high}, nil
}

// Overview holds the header summary of a single article, as returned by OVER.
type Overview struct {
	ArticleNum int
	Subject    string
	From       string
	Date       time.Time
	MessageID  string
	References string
	Bytes      int
	Lines      int
}

// parseInt parses a base-10 integer, returning 0 for any malformed input.
func parseInt(s string) int {
	n, _ := strconv.Atoi(strings.TrimSpace(s))
	return n
}

// parseDate parses an overview Date field, returning the zero time.Time when it
// can't be understood. The messy real-world format zoo (RFC 1123/822, 2-digit
// years, named-zone offsets like "... UTC"/"... EST") is handled by the shared
// go-datetime/dates parser so every fleet consumer benefits from one table.
func parseDate(s string) time.Time {
	t, _ := dates.Parse(s)
	return t
}

// Over returns the overview (header summaries) for the inclusive article range
// low-high in the currently selected group. It uses the RFC 3977 OVER command
// and, if the server rejects it as unknown (500/501), transparently falls back
// to the legacy XOVER command, which has an identical response format.
func (c *Conn) Over(low, high int) ([]Overview, error) {
	lines, err := c.multiCmd(224, "OVER %d-%d", low, high)
	if err != nil {
		if code := codeOf(err); code == 500 || code == 501 {
			lines, err = c.multiCmd(224, "XOVER %d-%d", low, high)
		}
		if err != nil {
			return nil, err
		}
	}
	out := make([]Overview, 0, len(lines))
	for _, line := range lines {
		f := strings.Split(line, "\t")
		if len(f) < 8 {
			continue
		}
		out = append(out, Overview{
			ArticleNum: parseInt(f[0]),
			Subject:    f[1],
			From:       f[2],
			Date:       parseDate(f[3]),
			MessageID:  strings.TrimSpace(f[4]),
			References: strings.TrimSpace(f[5]),
			Bytes:      parseInt(f[6]),
			Lines:      parseInt(f[7]),
		})
	}
	return out, nil
}

// Article is a complete article: canonicalized headers plus the raw body.
type Article struct {
	Headers map[string][]string
	Body    string
}

// Article fetches a full article by message-id ("<...>") or by article number,
// using the ARTICLE command. Headers are split from the body on the first blank
// line and canonicalized.
func (c *Conn) Article(msgIDorNum string) (*Article, error) {
	lines, err := c.multiCmd(220, "ARTICLE %s", msgIDorNum)
	if err != nil {
		return nil, err
	}
	headers := make(map[string][]string)
	i := 0
	for ; i < len(lines); i++ {
		if lines[i] == "" {
			i++
			break
		}
		idx := strings.Index(lines[i], ":")
		if idx < 0 {
			continue
		}
		key := textproto.CanonicalMIMEHeaderKey(strings.TrimSpace(lines[i][:idx]))
		val := strings.TrimSpace(lines[i][idx+1:])
		headers[key] = append(headers[key], val)
	}
	body := strings.Join(lines[i:], "\n")
	return &Article{Headers: headers, Body: body}, nil
}

// NewsgroupInfo describes an available newsgroup as listed by LIST ACTIVE.
type NewsgroupInfo struct {
	Name   string
	High   int
	Low    int
	Status string
}

// List returns the available newsgroups via LIST ACTIVE. If wildmat is
// non-empty it is passed to the server to filter the result.
func (c *Conn) List(wildmat string) ([]NewsgroupInfo, error) {
	cmd := "LIST ACTIVE"
	if wildmat != "" {
		cmd += " " + wildmat
	}
	lines, err := c.multiCmd(215, "%s", cmd)
	if err != nil {
		return nil, err
	}
	out := make([]NewsgroupInfo, 0, len(lines))
	for _, line := range lines {
		f := strings.Fields(line)
		if len(f) < 4 {
			continue
		}
		out = append(out, NewsgroupInfo{
			Name:   f[0],
			High:   parseInt(f[1]),
			Low:    parseInt(f[2]),
			Status: f[3],
		})
	}
	return out, nil
}

// Close sends QUIT (best effort) and closes the underlying connection.
func (c *Conn) Close() error {
	if id, err := c.text.Cmd("QUIT"); err == nil {
		c.text.StartResponse(id)
		_, _, _ = c.text.ReadCodeLine(205)
		c.text.EndResponse(id)
	}
	return c.text.Close()
}
