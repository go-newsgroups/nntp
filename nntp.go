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
	"fmt"
	"net"
	"net/textproto"
	"strconv"
	"strings"
	"time"
)

// Conn is a connection to an NNTP server. It wraps a *textproto.Conn layered
// over the underlying net.Conn. A Conn is not safe for concurrent use.
type Conn struct {
	conn net.Conn
	text *textproto.Conn
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
	id, _ := c.text.Cmd(format, args...)
	c.text.StartResponse(id)
	defer c.text.EndResponse(id)
	return c.text.ReadCodeLine(expect)
}

// multiCmd sends a command whose response is a status line followed by a
// dot-terminated multiline block, and returns the block's lines.
func (c *Conn) multiCmd(expect int, format string, args ...any) ([]string, error) {
	id, _ := c.text.Cmd(format, args...)
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
		return nil
	}
	return fmt.Errorf("nntp: AUTHINFO PASS rejected code %d: %s", code, msg)
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

// overDateLayouts are tried, in order, when parsing an overview Date field.
var overDateLayouts = []string{
	time.RFC1123Z,
	time.RFC1123,
	"02 Jan 2006 15:04:05 -0700",
}

// parseInt parses a base-10 integer, returning 0 for any malformed input.
func parseInt(s string) int {
	n, _ := strconv.Atoi(strings.TrimSpace(s))
	return n
}

// parseDate parses a date using the known overview layouts, returning the zero
// time.Time if none match.
func parseDate(s string) time.Time {
	s = strings.TrimSpace(s)
	for _, layout := range overDateLayouts {
		if t, err := time.Parse(layout, s); err == nil {
			return t
		}
	}
	return time.Time{}
}

// Over returns the overview (header summaries) for the inclusive article range
// low-high in the currently selected group, via the OVER command.
func (c *Conn) Over(low, high int) ([]Overview, error) {
	lines, err := c.multiCmd(224, "OVER %d-%d", low, high)
	if err != nil {
		return nil, err
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
	id, _ := c.text.Cmd("QUIT")
	c.text.StartResponse(id)
	_, _, _ = c.text.ReadCodeLine(205)
	c.text.EndResponse(id)
	return c.text.Close()
}
