package goproxy_test

import (
	"crypto/tls"
	"crypto/x509"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/elazarl/goproxy"
	"github.com/stretchr/testify/require"
)

func TestGenerateCA(t *testing.T) {
	t.Parallel()

	ca, err := goproxy.GenerateCA()
	require.NoError(t, err)
	require.NotNil(t, ca.Leaf)
	require.True(t, ca.Leaf.IsCA)
	require.NotZero(t, ca.Leaf.KeyUsage&x509.KeyUsageCertSign)
	require.Contains(t, ca.Leaf.Subject.CommonName, "GoProxy")

	otherCA, err := goproxy.GenerateCA()
	require.NoError(t, err)
	require.NotEqual(t, ca.Leaf.Raw, otherCA.Leaf.Raw)
	require.NotEqual(t, ca.PrivateKey, otherCA.PrivateKey)

	certPEM := goproxy.CACertPEM(ca)
	keyPEM, err := goproxy.CAKeyPEM(ca)
	require.NoError(t, err)

	parsedCA, err := goproxy.CAFromPEM(certPEM, keyPEM)
	require.NoError(t, err)
	require.Equal(t, ca.Leaf.Raw, parsedCA.Leaf.Raw)
	require.True(t, parsedCA.Leaf.IsCA)
}

func TestGlobalCAPEMIsUsable(t *testing.T) {
	t.Parallel()

	ca, err := goproxy.CAFromPEM(goproxy.CA_CERT, goproxy.CA_KEY)
	require.NoError(t, err)
	require.Equal(t, goproxy.GoproxyCa.Leaf.Raw, ca.Leaf.Raw)

	pool := x509.NewCertPool()
	require.True(t, pool.AppendCertsFromPEM(goproxy.CA_CERT))
}

func TestLoadOrCreateCAPersistsAndReloads(t *testing.T) {
	t.Parallel()

	caPath := filepath.Join(t.TempDir(), "nested")
	certFile := filepath.Join(caPath, "ca.pem")
	keyFile := filepath.Join(caPath, "key.pem")

	ca, err := goproxy.LoadOrCreateCA(certFile, keyFile)
	require.NoError(t, err)
	require.NotNil(t, ca.Leaf)

	keyInfo, err := os.Stat(keyFile)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o600), keyInfo.Mode().Perm())

	certInfo, err := os.Stat(certFile)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o644), certInfo.Mode().Perm())

	reloadedCA, err := goproxy.LoadOrCreateCA(certFile, keyFile)
	require.NoError(t, err)
	require.Equal(t, ca.Leaf.Raw, reloadedCA.Leaf.Raw)

	originalKeyPEM, err := goproxy.CAKeyPEM(ca)
	require.NoError(t, err)
	reloadedKeyPEM, err := goproxy.CAKeyPEM(reloadedCA)
	require.NoError(t, err)
	require.Equal(t, originalKeyPEM, reloadedKeyPEM)
}

func TestDefaultTLSVerificationIsEnabled(t *testing.T) {
	t.Parallel()

	proxy := goproxy.NewProxyHttpServer()
	require.False(t, proxy.Tr.TLSClientConfig.InsecureSkipVerify)

	ctx := &goproxy.ProxyCtx{Proxy: proxy}
	tlsConfig, err := goproxy.TLSConfigFromCA(&goproxy.GoproxyCa)("example.com:443", ctx)
	require.NoError(t, err)
	require.False(t, tlsConfig.InsecureSkipVerify)
	require.Len(t, tlsConfig.Certificates, 1)
}

func TestLoadOrCreateCAConcurrent(t *testing.T) {
	t.Parallel()

	caDir := t.TempDir()
	certFile := filepath.Join(caDir, "ca.pem")
	keyFile := filepath.Join(caDir, "key.pem")

	const goroutines = 8
	var waitGroup sync.WaitGroup
	certificates := make(chan *tls.Certificate, goroutines)
	errors := make(chan error, goroutines)

	for range goroutines {
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			ca, err := goproxy.LoadOrCreateCA(certFile, keyFile)
			if err != nil {
				errors <- err
				return
			}
			certificates <- ca
		}()
	}

	waitGroup.Wait()
	close(certificates)
	close(errors)

	for err := range errors {
		require.NoError(t, err)
	}

	var firstRaw []byte
	count := 0
	for ca := range certificates {
		if count == 0 {
			firstRaw = ca.Leaf.Raw
		}
		require.Equal(t, firstRaw, ca.Leaf.Raw)
		count++
	}
	require.Equal(t, goroutines, count)
}

func TestCertsFileDoesNotContainHardcodedCredentials(t *testing.T) {
	t.Parallel()

	source, err := os.ReadFile("certs.go")
	require.NoError(t, err)
	require.NotContains(t, string(source), "-----BEGIN RSA PRIVATE KEY-----")
	require.NotContains(t, string(source), "MIIJKAIBAAKCAgEAnhDL4")
	require.NotContains(t, string(source), "InsecureSkipVerify: true")
}
