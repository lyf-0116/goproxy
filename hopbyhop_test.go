package goproxy_test

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/elazarl/goproxy"
	"github.com/elazarl/goproxy/internal/signer"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// strippedRequestHeaders are hop-by-hop headers that must never reach the
// destination server, including the custom header named by Connection.
var strippedRequestHeaders = map[string]string{
	"Connection":          "keep-alive, X-Connection-Token",
	"Proxy-Connection":    "keep-alive",
	"Keep-Alive":          "timeout=5, max=100",
	"Proxy-Authenticate":  "Basic",
	"Proxy-Authorization": "Basic dXNlcjpwYXNz",
	"Te":                  "gzip",
	"Trailer":             "X-Expired",
	"Transfer-Encoding":   "chunked",
	"Upgrade":             "h2c",
	"X-Connection-Token":  "listed-in-connection",
}

// newHopHeaderBackend is a raw TCP backend that echoes back the request
// headers it received and emits hop-by-hop response headers. A raw listener
// (rather than httptest) is required because net/http rewrites the
// Connection header itself, which would hide whether the proxy parses the
// connection-specific field names per RFC 7230 §6.1.
func newHopHeaderBackend(t *testing.T, tlsBackend bool) (string, func()) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	var serverListener net.Listener
	if tlsBackend {
		cert, err := signer.SignHost(goproxy.GoproxyCa, []string{"127.0.0.1", "localhost"})
		require.NoError(t, err)
		serverListener = tls.NewListener(listener, &tls.Config{Certificates: []tls.Certificate{*cert}})
	} else {
		serverListener = listener
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, err := serverListener.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				reader := bufio.NewReader(conn)
				req, err := http.ReadRequest(reader)
				if err != nil {
					return
				}
				for name := range strippedRequestHeaders {
					if name == "Te" && req.ProtoMajor == 2 && req.Header.Get("Te") == "trailers" {
						continue
					}
					// http.Transport itself emits "Connection: close" when the
					// caller asked to close the request; the proxy-side stripping
					// of Connection is covered by the raw MITM test below.
					if name == "Connection" && req.Header.Get("Connection") == "close" {
						continue
					}
					assert.Empty(t, req.Header.Get(name),
						"hop-by-hop request header %q must not reach the destination", name)
				}
				assert.Equal(t, "kept", req.Header.Get("X-End-To-End"),
					"end-to-end request headers must be forwarded")

				// Drain the request body so the connection stays sane.
				_, _ = io.Copy(io.Discard, req.Body)

				response := "HTTP/1.1 200 OK\r\n" +
					"Connection: keep-alive, X-Resp-Connection-Token\r\n" +
					"Keep-Alive: timeout=5\r\n" +
					"Proxy-Connection: keep-alive\r\n" +
					"Proxy-Authenticate: Basic\r\n" +
					"Te: gzip\r\n" +
					"Upgrade: h2c\r\n" +
					"X-Resp-Connection-Token: listed-in-connection\r\n" +
					"X-End-To-End: kept\r\n" +
					"Content-Length: 2\r\n\r\n" +
					"ok"
				_, _ = io.WriteString(conn, response)
			}(conn)
		}
	}()

	scheme := "http"
	if tlsBackend {
		scheme = "https"
	}
	return scheme + "://" + listener.Addr().String(), func() {
		_ = listener.Close()
		<-done
	}
}

func addHopRequestHeaders(req *http.Request) {
	for name, value := range strippedRequestHeaders {
		req.Header.Set(name, value)
	}
	req.Header.Set("X-End-To-End", "kept")
}

func assertResponseHopHeadersStripped(t *testing.T, h http.Header) {
	t.Helper()
	for _, name := range []string{
		"Connection", "Keep-Alive", "Proxy-Connection",
		"Proxy-Authenticate", "Te", "Upgrade",
		"X-Resp-Connection-Token",
	} {
		assert.Empty(t, h.Get(name),
			"hop-by-hop response header %q must be stripped before the client", name)
	}
	assert.Equal(t, "kept", h.Get("X-End-To-End"),
		"end-to-end response headers must survive")
}

func TestHopByHopHeadersStrippedPlaintext(t *testing.T) {
	backendURL, cleanup := newHopHeaderBackend(t, false)
	defer cleanup()

	client, proxySrv := oneShotProxy(goproxy.NewProxyHttpServer())
	defer proxySrv.Close()

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, backendURL, nil)
	require.NoError(t, err)
	addHopRequestHeaders(req)

	resp, err := client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Equal(t, "ok", string(body))
	assertResponseHopHeadersStripped(t, resp.Header)
}

func TestHopByHopHeadersStrippedMitm(t *testing.T) {
	backendURL, cleanup := newHopHeaderBackend(t, true)
	defer cleanup()

	proxy := goproxy.NewProxyHttpServer()
	proxy.Tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	proxy.OnRequest().HandleConnect(goproxy.AlwaysMitm)

	proxySrv := httptest.NewServer(proxy)
	defer proxySrv.Close()

	// A raw client is required: http.Transport removes connection-listed
	// headers itself before the request leaves the process, which would hide
	// whether the proxy parses and strips them.
	conn, err := net.Dial("tcp", proxySrv.Listener.Addr().String())
	require.NoError(t, err)
	defer conn.Close()

	backendURLParsed, err := url.Parse(backendURL)
	require.NoError(t, err)
	connectTarget := backendURLParsed.Host

	connectReq, err := http.NewRequestWithContext(context.Background(), http.MethodConnect,
		"https://"+connectTarget, nil)
	require.NoError(t, err)
	require.NoError(t, connectReq.Write(conn))
	connectResp, err := http.ReadResponse(bufio.NewReader(conn), connectReq)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, connectResp.StatusCode)

	tlsConn := tls.Client(conn, &tls.Config{InsecureSkipVerify: true})
	require.NoError(t, tlsConn.HandshakeContext(context.Background()))

	rawReq := "GET / HTTP/1.1\r\n" +
		"Host: " + connectTarget + "\r\n" +
		"Connection: close, X-Connection-Token\r\n" +
		"Proxy-Connection: keep-alive\r\n" +
		"Keep-Alive: timeout=5, max=100\r\n" +
		"Proxy-Authenticate: Basic\r\n" +
		"Proxy-Authorization: Basic dXNlcjpwYXNz\r\n" +
		"Te: gzip\r\n" +
		"Trailer: X-Expired\r\n" +
		"Upgrade: h2c\r\n" +
		"X-Connection-Token: listed-in-connection\r\n" +
		"X-End-To-End: kept\r\n\r\n"
	_, err = tlsConn.Write([]byte(rawReq))
	require.NoError(t, err)

	reader := bufio.NewReader(tlsConn)
	resp, err := http.ReadResponse(reader, nil)
	require.NoError(t, err)
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Equal(t, "ok", string(body))
	assertResponseHopHeadersStripped(t, resp.Header)
}

func TestHopByHopHeadersStrippedHTTP2(t *testing.T) {
	backendURL, cleanup := newHopHeaderBackend(t, true)
	defer cleanup()

	proxy := goproxy.NewProxyHttpServer()
	proxy.AllowHTTP2 = true
	proxy.Tr = &http.Transport{
		ForceAttemptHTTP2: true,
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"h2"}},
	}
	proxy.OnRequest().HandleConnect(goproxy.AlwaysMitm)

	proxySrv := httptest.NewServer(proxy)
	defer proxySrv.Close()

	client := createProxyClientH2(t, proxySrv.URL)

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, backendURL, nil)
	require.NoError(t, err)
	addHopRequestHeaders(req)
	// The HTTP/2 transport rejects these on the client side; the proxy-side
	// stripping of the h2-specific set is covered by the internal unit tests.
	req.Header.Del("Upgrade")
	req.Header.Del("Transfer-Encoding")
	req.Header.Del("Connection")
	// A field named by Connection cannot be exercised end-to-end over h2
	// either: HTTP/2 has no Connection header to name it. The raw HTTP/1.x
	// MITM test covers RFC 7230 §6.1 token parsing.
	req.Header.Del("X-Connection-Token")
	req.Header.Set("Te", "trailers")

	resp, err := client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Equal(t, "ok", string(body))
	assertResponseHopHeadersStripped(t, resp.Header)
}

// TestHopByHopChunkedAndTrailersPassThrough guards the framing headers that
// the response strip helpers must never remove.
func TestHopByHopChunkedAndTrailersPassThrough(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Trailer", "X-Server-Trailer")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "chunked-body")
		w.Header().Set("X-Server-Trailer", "trailer-value")
	}))
	defer upstream.Close()

	client, proxySrv := oneShotProxy(goproxy.NewProxyHttpServer())
	defer proxySrv.Close()

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, upstream.URL, nil)
	require.NoError(t, err)
	resp, err := client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Equal(t, "chunked-body", string(body))
	assert.Equal(t, "trailer-value", resp.Trailer.Get("X-Server-Trailer"))
}

// TestMitmTrailerHeaderPassthrough verifies that the MITM response path,
// which writes straight onto the raw connection, keeps the Trailer header
// rather than treating it as a strip candidate.
func TestMitmTrailerHeaderPassthrough(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()

	cert, err := signer.SignHost(goproxy.GoproxyCa, []string{"127.0.0.1", "localhost"})
	require.NoError(t, err)
	tlsListener := tls.NewListener(listener, &tls.Config{Certificates: []tls.Certificate{*cert}})

	go func() {
		conn, err := tlsListener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		if _, err := http.ReadRequest(bufio.NewReader(conn)); err != nil {
			return
		}
		_, _ = io.WriteString(conn, "HTTP/1.1 200 OK\r\n"+
			"Trailer: X-Server-Trailer\r\n"+
			"Transfer-Encoding: chunked\r\n\r\n"+
			"4\r\nwiki\r\n"+
			"0\r\n"+
			"X-Server-Trailer: trailer-value\r\n\r\n")
	}()

	proxy := goproxy.NewProxyHttpServer()
	proxy.Tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	proxy.OnRequest().HandleConnect(goproxy.AlwaysMitm)
	proxySrv := httptest.NewServer(proxy)
	defer proxySrv.Close()

	conn, err := net.Dial("tcp", proxySrv.Listener.Addr().String())
	require.NoError(t, err)
	defer conn.Close()

	connectReq, err := http.NewRequestWithContext(context.Background(), http.MethodConnect,
		"https://"+listener.Addr().String(), nil)
	require.NoError(t, err)
	require.NoError(t, connectReq.Write(conn))
	connectResp, err := http.ReadResponse(bufio.NewReader(conn), connectReq)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, connectResp.StatusCode)

	tlsConn := tls.Client(conn, &tls.Config{InsecureSkipVerify: true})
	require.NoError(t, tlsConn.HandshakeContext(context.Background()))

	_, err = fmt.Fprintf(tlsConn, "GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n",
		listener.Addr().String())
	require.NoError(t, err)

	resp, err := http.ReadResponse(bufio.NewReader(tlsConn), nil)
	require.NoError(t, err)
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Equal(t, "wiki", string(body))
	// net/http moves the Trailer announcement into resp.Trailer while
	// parsing a chunked response; resp.Write re-emits it on the way out, so
	// stripping must never touch the trailer machinery itself.
	assert.Equal(t, "trailer-value", resp.Trailer.Get("X-Server-Trailer"))
}
