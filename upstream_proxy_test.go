package goproxy_test

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/elazarl/goproxy"
	"github.com/stretchr/testify/require"
)

const (
	upstreamProxyUser = "foo"
	upstreamProxyPass = "bar"
)

func init() {
	// The CI/dev environment may point HTTP_PROXY at an unrelated local
	// proxy; tests here exercise their own explicit proxy chains and must
	// not inherit ambient proxy settings.
	for _, key := range []string{"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY"} {
		_ = os.Unsetenv(key)
		_ = os.Unsetenv(strings.ToLower(key))
	}
}

func upstreamProxyAuthHeader() string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(upstreamProxyUser+":"+upstreamProxyPass))
}

// upstreamProxyRecorder is a minimal authenticating forward proxy used as the
// upstream hop. It records every Proxy-Authorization header it sees and
// rejects any request missing the expected credential.
type upstreamProxyRecorder struct {
	t           *testing.T
	mu          sync.Mutex
	authHeaders []string
}

func (p *upstreamProxyRecorder) recordAuth(value string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.authHeaders = append(p.authHeaders, value)
}

func (p *upstreamProxyRecorder) authSnapshot() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]string, len(p.authHeaders))
	copy(out, p.authHeaders)
	return out
}

func (p *upstreamProxyRecorder) checkAuth(w http.ResponseWriter, r *http.Request) bool {
	got := r.Header.Get("Proxy-Authorization")
	p.recordAuth(got)
	if got != upstreamProxyAuthHeader() {
		w.Header().Set("Proxy-Authenticate", `Basic realm="upstream"`)
		w.WriteHeader(http.StatusProxyAuthRequired)
		_, _ = io.WriteString(w, "missing upstream credentials")
		return false
	}
	return true
}

func (p *upstreamProxyRecorder) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !p.checkAuth(w, r) {
		return
	}
	if r.Method == http.MethodConnect {
		p.handleConnect(w, r)
		return
	}
	// Plain HTTP proxying: forward the absolute-form request and record what
	// the origin would actually receive.
	r.RequestURI = ""
	// A conformant proxy consumes hop-by-hop headers before forwarding.
	r.Header.Del("Proxy-Authorization")
	r.Header.Del("Proxy-Connection")
	r.Header.Del("Connection")
	resp, err := http.DefaultTransport.RoundTrip(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	for k, vs := range resp.Header {
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

func (p *upstreamProxyRecorder) handleConnect(w http.ResponseWriter, r *http.Request) {
	hj, ok := w.(http.Hijacker)
	require.True(p.t, ok, "test server must support hijacking")
	client, _, err := hj.Hijack()
	require.NoError(p.t, err)
	defer client.Close()

	target, err := net.Dial("tcp", r.Host)
	if err != nil {
		_, _ = io.WriteString(client, "HTTP/1.1 502 Bad Gateway\r\n\r\n")
		return
	}
	defer target.Close()
	_, _ = io.WriteString(client, "HTTP/1.1 200 Connection established\r\n\r\n")

	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(target, client); done <- struct{}{} }()
	go func() { _, _ = io.Copy(client, target); done <- struct{}{} }()
	<-done
}

func newUpstreamProxy(t *testing.T) (*httptest.Server, *upstreamProxyRecorder) {
	t.Helper()
	rec := &upstreamProxyRecorder{t: t}
	srv := httptest.NewServer(rec)
	t.Cleanup(srv.Close)
	t.Cleanup(func() {
		// sanity: every request reaching the upstream carried credentials
		require.NotEmpty(t, rec.authSnapshot(), "upstream proxy received no requests")
	})
	return srv, rec
}

func proxyURLWithCreds(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	require.NoError(t, err)
	u.User = url.UserPassword(upstreamProxyUser, upstreamProxyPass)
	return u
}

// TestUpstreamProxyAuthHTTP verifies that plain-HTTP requests forwarded to an
// authenticated upstream proxy carry Proxy-Authorization on the proxy hop,
// while the header never reaches the origin server.
func TestUpstreamProxyAuthHTTP(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Empty(t, r.Header.Get("Proxy-Authorization"),
			"origin must never receive the upstream proxy credential")
		_, _ = io.WriteString(w, "ok")
	}))
	defer origin.Close()

	upstream, _ := newUpstreamProxy(t)

	proxy := goproxy.NewProxyHttpServer()
	proxy.Tr.Proxy = http.ProxyURL(proxyURLWithCreds(t, upstream.URL))
	client, listener := oneShotProxy(proxy)
	defer listener.Close()

	resp, err := client.Get(origin.URL)
	require.NoError(t, err)
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Equal(t, "ok", string(body))
}

// TestUpstreamProxyAuthMITM covers MITM mode, where the decrypted requests are
// forwarded through http.Transport with an authenticated upstream proxy.
func TestUpstreamProxyAuthMITM(t *testing.T) {
	upstream, rec := newUpstreamProxy(t)

	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Empty(t, r.Header.Get("Proxy-Authorization"),
			"origin must never receive the upstream proxy credential")
		_, _ = io.WriteString(w, "mitm-ok")
	}))
	defer origin.Close()

	proxy := goproxy.NewProxyHttpServer()
	proxy.OnRequest().HandleConnect(goproxy.AlwaysMitm)
	proxy.Tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	proxy.Tr.Proxy = http.ProxyURL(proxyURLWithCreds(t, upstream.URL))

	client, listener := oneShotProxy(proxy)
	defer listener.Close()

	resp, err := client.Get(origin.URL)
	require.NoError(t, err)
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	require.NoError(t, err)
	require.Equal(t, "mitm-ok", string(body))

	require.NotEmpty(t, rec.authSnapshot())
	for _, auth := range rec.authSnapshot() {
		require.Equal(t, upstreamProxyAuthHeader(), auth)
	}
}

// dialThroughProxy opens a raw CONNECT tunnel via the goproxy listener and
// returns the tunneled connection to the target address.
func dialThroughProxy(t *testing.T, listener *httptest.Server, target string) net.Conn {
	t.Helper()
	conn, err := net.Dial("tcp", listener.Listener.Addr().String())
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })

	connectReq := &http.Request{
		Method: http.MethodConnect,
		URL:    &url.URL{Opaque: target},
		Host:   target,
		Header: make(http.Header),
	}
	require.NoError(t, connectReq.Write(conn))
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, connectReq)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode, "CONNECT tunnel rejected: %s", resp.Status)
	return &readBufferedTestConn{Conn: conn, r: br}
}

type readBufferedTestConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *readBufferedTestConn) Read(p []byte) (int, error) { return c.r.Read(p) }

// TestUpstreamProxyAuthCONNECT verifies credentials are attached to the
// CONNECT request dialed through an authenticated plaintext upstream proxy
// when goproxy tunnels a client CONNECT.
func TestUpstreamProxyAuthCONNECT(t *testing.T) {
	upstream, rec := newUpstreamProxy(t)

	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Empty(t, r.Header.Get("Proxy-Authorization"),
			"origin must never receive the upstream proxy credential")
		_, _ = io.WriteString(w, "tunnel-ok")
	}))
	defer origin.Close()

	proxy := goproxy.NewProxyHttpServer()
	proxy.ConnectDial = proxy.NewConnectDialToProxyWithHandler(upstream.URL, func(req *http.Request) {
		req.Header.Set("Proxy-Authorization", upstreamProxyAuthHeader())
	})

	_, listener := oneShotProxy(proxy)
	defer listener.Close()

	tunnel := dialThroughProxy(t, listener, origin.Listener.Addr().String())
	require.NoError(t, (&http.Request{
		Method: http.MethodGet,
		URL:    &url.URL{Path: "/"},
		Host:   origin.Listener.Addr().String(),
		Header: make(http.Header),
	}).Write(tunnel))

	resp, err := http.ReadResponse(bufio.NewReader(tunnel), nil)
	require.NoError(t, err)
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.Equal(t, "tunnel-ok", string(body))

	for _, auth := range rec.authSnapshot() {
		require.Equal(t, upstreamProxyAuthHeader(), auth)
	}
}

// TestUpstreamProxyAuthHTTPS verifies the TLS upstream proxy path uses the
// dedicated UpstreamProxyTLSClientConfig and still authenticates the CONNECT.
func TestUpstreamProxyAuthHTTPS(t *testing.T) {
	upstream, rec := newUpstreamProxy(t)
	tlsUpstream := httptest.NewTLSServer(upstream.Config.Handler)
	defer tlsUpstream.Close()

	caPool := x509.NewCertPool()
	caPool.AddCert(tlsUpstream.Certificate())

	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "tls-tunnel-ok")
	}))
	defer origin.Close()

	proxy := goproxy.NewProxyHttpServer()
	// Deliberately disable verification on the origin-facing config. The
	// upstream proxy connection must not inherit this insecure setting.
	proxy.Tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	proxy.UpstreamProxyTLSClientConfig = &tls.Config{RootCAs: caPool}
	proxy.ConnectDial = proxy.NewConnectDialToProxyWithHandler(tlsUpstream.URL, func(req *http.Request) {
		req.Header.Set("Proxy-Authorization", upstreamProxyAuthHeader())
	})

	_, listener := oneShotProxy(proxy)
	defer listener.Close()

	tunnel := dialThroughProxy(t, listener, origin.Listener.Addr().String())
	require.NoError(t, (&http.Request{
		Method: http.MethodGet,
		URL:    &url.URL{Path: "/"},
		Host:   origin.Listener.Addr().String(),
		Header: make(http.Header),
	}).Write(tunnel))

	resp, err := http.ReadResponse(bufio.NewReader(tunnel), nil)
	require.NoError(t, err)
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.Equal(t, "tls-tunnel-ok", string(body))

	for _, auth := range rec.authSnapshot() {
		require.Equal(t, upstreamProxyAuthHeader(), auth)
	}
}

// TestUpstreamProxyTLSVerifiedByDefault proves an HTTPS upstream proxy with an
// untrusted certificate is rejected when no dedicated config is provided,
// instead of silently reusing an insecure origin-facing config.
func TestUpstreamProxyTLSVerifiedByDefault(t *testing.T) {
	tlsUpstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer tlsUpstream.Close()

	proxy := goproxy.NewProxyHttpServer()
	proxy.Tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	dial := proxy.NewConnectDialToProxyWithHandler(tlsUpstream.URL, func(req *http.Request) {
		req.Header.Set("Proxy-Authorization", upstreamProxyAuthHeader())
	})
	require.NotNil(t, dial)

	_, err := dial("tcp", "example.com:443")
	var certErr *tls.CertificateVerificationError
	require.ErrorAs(t, err, &certErr)
}

// TestProxyAuthorizationStrippedWhenDirect confirms a Proxy-Authorization
// header sent by the client is consumed at this hop and not leaked to the
// origin when no upstream proxy is configured.
func TestProxyAuthorizationStrippedWhenDirect(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Empty(t, r.Header.Get("Proxy-Authorization"),
			"upstream credential leaked to origin on direct connection")
		require.Empty(t, r.Header.Get("Proxy-Connection"))
		_, _ = io.WriteString(w, "direct-ok")
	}))
	defer origin.Close()

	proxy := goproxy.NewProxyHttpServer()
	proxy.Tr.Proxy = nil
	client, listener := oneShotProxy(proxy)
	defer listener.Close()

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, origin.URL, nil)
	require.NoError(t, err)
	req.Header.Set("Proxy-Authorization", upstreamProxyAuthHeader())
	req.Header.Set("Proxy-Connection", "keep-alive")

	resp, err := client.Do(req)
	require.NoError(t, err)
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	require.NoError(t, err)
	require.Equal(t, "direct-ok", string(body))
}

// TestCONNECTRejectedErrorBody verifies that a rejected CONNECT surfaces the
// (length-capped) upstream error body in the returned dial error, on the
// plaintext upstream path.
func TestCONNECTRejectedErrorBody(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusProxyAuthRequired)
		_, _ = io.WriteString(w, "upstream says no")
	}))
	defer upstream.Close()

	proxy := goproxy.NewProxyHttpServer()
	dial := proxy.NewConnectDialToProxy(upstream.URL)
	require.NotNil(t, dial)

	_, err := dial("tcp", "example.com:443")
	require.Error(t, err)
	require.Contains(t, err.Error(), "upstream says no")
}
