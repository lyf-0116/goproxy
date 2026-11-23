package goproxy

import (
	"net/http"
	"testing"
)

func headerWith(kv ...string) http.Header {
	h := make(http.Header)
	for i := 0; i < len(kv); i += 2 {
		h.Set(kv[i], kv[i+1])
	}
	return h
}

func TestRemoveHTTP1RequestHopByHopHeaders(t *testing.T) {
	h := headerWith(
		"Connection", `keep-alive, X-Foo`,
		"Proxy-Connection", "keep-alive",
		"Keep-Alive", "timeout=5",
		"Proxy-Authenticate", "auth",
		"Proxy-Authorization", "auth",
		"Te", "gzip",
		"Trailer", "X-Expired",
		"Transfer-Encoding", "chunked",
		"Upgrade", "h2c",
		"X-Foo", "connection-listed",
		"X-End-To-End", "kept",
	)

	removeHTTP1RequestHopByHopHeaders(h)

	for _, name := range []string{
		"Connection", "Proxy-Connection", "Keep-Alive", "Proxy-Authenticate",
		"Proxy-Authorization", "Te", "Trailer", "Transfer-Encoding",
		"Upgrade", "X-Foo",
	} {
		if h.Get(name) != "" {
			t.Errorf("request header %q should have been stripped, got %q", name, h.Get(name))
		}
	}
	if got := h.Get("X-End-To-End"); got != "kept" {
		t.Errorf("end-to-end header must survive, got %q", got)
	}
}

func TestRemoveHTTP1RequestKeepsUpgradeHandshake(t *testing.T) {
	h := headerWith(
		"Connection", "Upgrade",
		"Upgrade", "websocket",
		"X-End-To-End", "kept",
	)

	removeHTTP1RequestHopByHopHeaders(h)

	if got := h.Get("Connection"); got != "Upgrade" {
		t.Errorf("Connection header must be retained for upgrade, got %q", got)
	}
	if got := h.Get("Upgrade"); got != "websocket" {
		t.Errorf("Upgrade header must be retained for upgrade, got %q", got)
	}
}

func TestRemoveHTTP2RequestHopByHopHeaders(t *testing.T) {
	h := headerWith(
		"Connection", `close, X-Foo`,
		"Keep-Alive", "timeout=5",
		"Proxy-Connection", "keep-alive",
		"Transfer-Encoding", "chunked",
		"Upgrade", "h2c",
		"Proxy-Authenticate", "auth",
		"Proxy-Authorization", "auth",
		"Te", "gzip",
		"Trailer", "X-Expired",
		"X-Foo", "connection-listed",
		"X-End-To-End", "kept",
	)

	removeHTTP2RequestHopByHopHeaders(h)

	for _, name := range []string{
		"Connection", "Keep-Alive", "Proxy-Connection", "Transfer-Encoding",
		"Upgrade", "Proxy-Authenticate", "Proxy-Authorization", "Te",
		"Trailer", "X-Foo",
	} {
		if h.Get(name) != "" {
			t.Errorf("h2 request header %q should have been stripped, got %q", name, h.Get(name))
		}
	}
	if got := h.Get("X-End-To-End"); got != "kept" {
		t.Errorf("end-to-end header must survive, got %q", got)
	}
}

func TestRemoveHTTP2RequestKeepsTeTrailers(t *testing.T) {
	h := headerWith("Te", "trailers")
	removeHTTP2RequestHopByHopHeaders(h)
	if got := h.Get("Te"); got != "trailers" {
		t.Errorf(`TE: trailers is legal in HTTP/2, got %q`, got)
	}

	h = headerWith("Te", "trailers, gzip")
	removeHTTP2RequestHopByHopHeaders(h)
	if h.Get("Te") != "" {
		t.Errorf("non-trailers TE values must be stripped, got %q", h.Get("Te"))
	}
}

func TestRemoveHTTP1ResponseHopByHopHeaders(t *testing.T) {
	h := headerWith(
		"Connection", `keep-alive, X-Foo`,
		"Proxy-Connection", "keep-alive",
		"Keep-Alive", "timeout=5",
		"Proxy-Authenticate", "auth",
		"Proxy-Authorization", "auth",
		"Te", "gzip",
		"Upgrade", "h2c",
		"X-Foo", "connection-listed",
		"X-End-To-End", "kept",
		// Framing/trailer headers must pass through.
		"Transfer-Encoding", "chunked",
		"Trailer", "X-Trailer",
	)

	removeHTTP1ResponseHopByHopHeaders(h)

	for _, name := range []string{
		"Connection", "Proxy-Connection", "Keep-Alive", "Proxy-Authenticate",
		"Proxy-Authorization", "Te", "Upgrade", "X-Foo",
	} {
		if h.Get(name) != "" {
			t.Errorf("response header %q should have been stripped, got %q", name, h.Get(name))
		}
	}
	if got := h.Get("Transfer-Encoding"); got != "chunked" {
		t.Errorf("Transfer-Encoding must be retained, got %q", got)
	}
	if got := h.Get("Trailer"); got != "X-Trailer" {
		t.Errorf("Trailer must be retained, got %q", got)
	}
	if got := h.Get("X-End-To-End"); got != "kept" {
		t.Errorf("end-to-end header must survive, got %q", got)
	}
}

func TestRemoveHTTP1ResponseKeepsUpgradeHandshake(t *testing.T) {
	h := headerWith(
		"Connection", "Upgrade",
		"Upgrade", "websocket",
		"X-End-To-End", "kept",
	)

	removeHTTP1ResponseHopByHopHeaders(h)

	if got := h.Get("Connection"); got != "Upgrade" {
		t.Errorf("Connection header must be retained for upgrade, got %q", got)
	}
	if got := h.Get("Upgrade"); got != "websocket" {
		t.Errorf("Upgrade header must be retained for upgrade, got %q", got)
	}
}

func TestRemoveHTTP2ResponseHopByHopHeaders(t *testing.T) {
	h := headerWith(
		"Connection", `close, X-Foo`,
		"Keep-Alive", "timeout=5",
		"Proxy-Connection", "keep-alive",
		"Transfer-Encoding", "chunked",
		"Upgrade", "h2c",
		"Proxy-Authenticate", "auth",
		"Proxy-Authorization", "auth",
		"Te", "gzip",
		"X-Foo", "connection-listed",
		"X-End-To-End", "kept",
		"Trailer", "X-Trailer",
	)

	removeHTTP2ResponseHopByHopHeaders(h)

	for _, name := range []string{
		"Connection", "Keep-Alive", "Proxy-Connection", "Transfer-Encoding",
		"Upgrade", "Proxy-Authenticate", "Proxy-Authorization", "Te",
		"X-Foo",
	} {
		if h.Get(name) != "" {
			t.Errorf("h2 response header %q should have been stripped, got %q", name, h.Get(name))
		}
	}
	if got := h.Get("Trailer"); got != "X-Trailer" {
		t.Errorf("Trailer must be retained, got %q", got)
	}
	if got := h.Get("X-End-To-End"); got != "kept" {
		t.Errorf("end-to-end header must survive, got %q", got)
	}
}

func TestRemoveConnectionTokensNonCanonicalKeys(t *testing.T) {
	// PreventCanonicalization keeps raw, non-canonical header keys. The
	// Connection-listed field must still be removed regardless of casing.
	h := http.Header{}
	h["x-lower-token"] = []string{"raw"}
	h.Set("X-Lower-Token", "canon")
	h.Set("Connection", "keep-alive, x-lower-token")

	removeConnectionTokens(h)

	if _, ok := h["x-lower-token"]; ok {
		t.Errorf("raw non-canonical key must be removed: %v", h)
	}
	if _, ok := h["X-Lower-Token"]; ok {
		t.Errorf("canonical key must be removed: %v", h)
	}
}

func TestRemoveConnectionTokensMultipleHeaderValues(t *testing.T) {
	h := headerWith(
		"Connection", "keep-alive, X-One",
		"X-One", "1",
		"X-Two", "2",
		"X-Kept", "yes",
	)
	h.Add("Connection", "X-Two")

	removeConnectionTokens(h)

	if h.Get("X-One") != "" || h.Get("X-Two") != "" {
		t.Errorf("tokens from every Connection value must be removed: %v", h)
	}
	if h.Get("X-Kept") != "yes" {
		t.Errorf("unlisted header must survive: %v", h)
	}
}
