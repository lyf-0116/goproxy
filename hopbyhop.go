package goproxy

import (
	"net/http"
	"net/textproto"
	"strings"
)

// Hop-by-hop header lists are maintained separately per direction (request
// vs. response) and per protocol (HTTP/1.x vs. HTTP/2): the four paths have
// different rules. In particular, response framing headers
// (Transfer-Encoding and Trailer) must be kept on the response paths, while
// HTTP/2 bans the whole HTTP/1.x connection-specific set outright
// (RFC 9113 §8.2.2). There is deliberately no single shared strip function.

// http1RequestHopByHopHeaders are the fixed hop-by-hop headers that must not
// cross a proxy hop on an HTTP/1.x request, per RFC 7230 §6.1 and the
// obsoleted RFC 2616 §13.5.1 (the latter for backward compatibility).
var http1RequestHopByHopHeaders = []string{
	"Connection",
	"Proxy-Connection", // non-standard, but sent by e.g. curl
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"Te",
	"Trailer",
	"Transfer-Encoding",
	"Upgrade",
}

// http2ConnectionSpecificHeaders are illegal in HTTP/2 requests and responses
// (RFC 9113 §8.2.2).
var http2ConnectionSpecificHeaders = []string{
	"Connection",
	"Keep-Alive",
	"Proxy-Connection",
	"Transfer-Encoding",
	"Upgrade",
}

// http2RequestHopByHopHeaders additionally covers headers that are
// hop-by-hop on a request even though they are not connection-specific.
var http2RequestHopByHopHeaders = []string{
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"Te",
	"Trailer",
}

// http1ResponseHopByHopHeaders are stripped from HTTP/1.x responses before
// they are written back to the client. Transfer-Encoding and Trailer are
// intentionally absent: the former carries the body framing (chunked) and the
// latter announces the trailing fields, both must pass through untouched.
var http1ResponseHopByHopHeaders = []string{
	"Connection",
	"Proxy-Connection",
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"Te",
	"Upgrade",
}

// http2ResponseHopByHopHeaders are stripped from HTTP/2 responses. As on the
// HTTP/1.x response path, Trailer is kept so trailing fields survive.
var http2ResponseHopByHopHeaders = []string{
	"Connection",
	"Keep-Alive",
	"Proxy-Connection",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"Te",
	"Upgrade",
}

// removeConnectionTokens removes every header field named in a Connection
// header value. RFC 7230 §6.1 requires proxies to parse the Connection header
// and strip the listed fields before forwarding, in addition to removing the
// Connection header itself.
func removeConnectionTokens(h http.Header) {
	var tokens []string
	for _, value := range h.Values("Connection") {
		for _, token := range strings.Split(value, ",") {
			token = textproto.TrimString(token)
			if token != "" {
				tokens = append(tokens, token)
			}
		}
	}
	for _, token := range tokens {
		// Header.Del canonicalizes the name, which misses raw, non-canonical
		// keys kept when PreventCanonicalization is enabled; match every key
		// case-insensitively so those fields are stripped as well.
		for key := range h {
			if strings.EqualFold(key, token) {
				delete(h, key)
			}
		}
	}
}

// removeHTTP1RequestHopByHopHeaders strips hop-by-hop headers from an
// HTTP/1.x request bound for the next hop. The Connection header is parsed
// for connection-specific field names, except during an Upgrade handshake
// (e.g. WebSocket), where the whole Connection/Upgrade pair must be retained.
func removeHTTP1RequestHopByHopHeaders(h http.Header) {
	upgradeHandshake := headerContains(h, "Connection", "Upgrade")
	if !upgradeHandshake {
		removeConnectionTokens(h)
	}
	for _, name := range http1RequestHopByHopHeaders {
		if upgradeHandshake && (name == "Connection" || name == "Upgrade") {
			continue
		}
		h.Del(name)
	}
}

// removeHTTP2RequestHopByHopHeaders strips connection-specific and other
// hop-by-hop headers from an HTTP/2 request (RFC 9113 §8.2.2). "TE" is legal
// in HTTP/2 only with the value "trailers", which is preserved.
func removeHTTP2RequestHopByHopHeaders(h http.Header) {
	removeConnectionTokens(h)
	for _, name := range http2ConnectionSpecificHeaders {
		h.Del(name)
	}
	for _, name := range http2RequestHopByHopHeaders {
		if name == "Te" && teIsOnlyTrailers(h) {
			h.Set("Te", "trailers")
			continue
		}
		h.Del(name)
	}
}

// removeHTTP1ResponseHopByHopHeaders strips hop-by-hop headers from an
// HTTP/1.x response before it reaches the client. Transfer-Encoding and
// Trailer are preserved so chunked bodies and trailing fields keep working.
// A 101 Switching Protocols response keeps its Connection/Upgrade headers,
// since they are part of the upgrade handshake.
func removeHTTP1ResponseHopByHopHeaders(h http.Header) {
	upgradeHandshake := headerContains(h, "Connection", "Upgrade")
	if !upgradeHandshake {
		removeConnectionTokens(h)
	}
	for _, name := range http1ResponseHopByHopHeaders {
		if upgradeHandshake && (name == "Connection" || name == "Upgrade") {
			continue
		}
		h.Del(name)
	}
}

// removeHTTP2ResponseHopByHopHeaders strips connection-specific and other
// hop-by-hop headers from an HTTP/2 response (RFC 9113 §8.2.2). The Trailer
// header is not touched and Transfer-Encoding is never emitted over HTTP/2
// anyway, so trailer forwarding remains intact.
func removeHTTP2ResponseHopByHopHeaders(h http.Header) {
	removeConnectionTokens(h)
	for _, name := range http2ConnectionSpecificHeaders {
		h.Del(name)
	}
	for _, name := range http2ResponseHopByHopHeaders {
		if name == "Te" && teIsOnlyTrailers(h) {
			h.Set("Te", "trailers")
			continue
		}
		h.Del(name)
	}
}

// teIsOnlyTrailers reports whether the TE header carries exactly one
// "trailers" value, the only one permitted in HTTP/2 (RFC 9113 §8.2.2).
func teIsOnlyTrailers(h http.Header) bool {
	values := h.Values("Te")
	if len(values) != 1 {
		return false
	}
	tokens := strings.Split(values[0], ",")
	if len(tokens) != 1 {
		return false
	}
	return strings.EqualFold(textproto.TrimString(tokens[0]), "trailers")
}
