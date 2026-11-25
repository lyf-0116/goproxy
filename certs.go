package goproxy

import (
	"crypto/tls"
)

// GoproxyCa is the root CA used by the default MITM actions.
//
// Package initialization loads a persistent CA from DefaultCAFilePaths when
// possible. If persistence is unavailable, it generates an ephemeral CA for
// the current process. Deployments that need a stable trust root should call
// LoadOrCreateCA from an explicit, protected path and pass the result to
// TLSConfigFromCA. The private key is never compiled into the package.
var GoproxyCa tls.Certificate

var (
	// CA_CERT contains the PEM-encoded certificate for GoproxyCa.
	// It is populated at runtime so clients can export and trust this CA.
	CA_CERT []byte

	// CA_KEY contains the PEM-encoded private key for GoproxyCa.
	// It remains in process memory for compatibility and must be protected.
	CA_KEY []byte
)

func init() {
	ca, err := LoadOrCreateDefaultCA()
	if err != nil {
		ca, err = GenerateCA()
		if err != nil {
			panic("Error generating CA: " + err.Error())
		}
	}

	keyPEM, err := CAKeyPEM(ca)
	if err != nil {
		panic("Error encoding CA private key: " + err.Error())
	}

	GoproxyCa = *ca
	CA_CERT = CACertPEM(ca)
	CA_KEY = keyPEM
}

var tlsClientSkipVerify = &tls.Config{
	InsecureSkipVerify: false,
	MinVersion:         tls.VersionTLS12,
}

var defaultTLSConfig = &tls.Config{
	InsecureSkipVerify: false,
	MinVersion:         tls.VersionTLS12,
}
