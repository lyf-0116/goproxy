package goproxy

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"sync"
	"time"
)

var caLoadMu sync.Mutex

// GenerateCA creates a new self-signed root certificate authority.
// The private key is generated in memory and is not shared with other deployments.
func GenerateCA() (*tls.Certificate, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("generate CA private key: %w", err)
	}

	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return nil, fmt.Errorf("generate CA serial number: %w", err)
	}

	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"GoProxy"},
			CommonName:   "GoProxy Local CA",
		},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, fmt.Errorf("create CA certificate: %w", err)
	}

	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("parse generated CA certificate: %w", err)
	}

	return &tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  privateKey,
		Leaf:        leaf,
	}, nil
}

// GenerateCACertificate is an alias for GenerateCA.
func GenerateCACertificate() (*tls.Certificate, error) {
	return GenerateCA()
}

// CAFromPEM parses a PEM-encoded CA certificate and private key.
func CAFromPEM(certPEM, keyPEM []byte) (*tls.Certificate, error) {
	ca, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("parse CA key pair: %w", err)
	}

	if ca.Leaf == nil {
		ca.Leaf, err = x509.ParseCertificate(ca.Certificate[0])
		if err != nil {
			return nil, fmt.Errorf("parse CA certificate: %w", err)
		}
	}
	if !ca.Leaf.IsCA {
		return nil, errors.New("certificate is not a certificate authority")
	}

	return &ca, nil
}

// LoadCA is an alias for CAFromPEM.
func LoadCA(certPEM, keyPEM []byte) (*tls.Certificate, error) {
	return CAFromPEM(certPEM, keyPEM)
}

// CACertPEM encodes the CA certificate as PEM.
func CACertPEM(ca *tls.Certificate) []byte {
	if ca == nil {
		return nil
	}

	var raw []byte
	switch {
	case ca.Leaf != nil:
		raw = ca.Leaf.Raw
	case len(ca.Certificate) > 0:
		raw = ca.Certificate[0]
	default:
		return nil
	}

	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: raw})
}

// CAKeyPEM encodes the CA private key as PKCS#1, SEC1, or PKCS#8 PEM.
func CAKeyPEM(ca *tls.Certificate) ([]byte, error) {
	if ca == nil || ca.PrivateKey == nil {
		return nil, errors.New("CA private key is unavailable")
	}

	var block *pem.Block
	switch privateKey := ca.PrivateKey.(type) {
	case *rsa.PrivateKey:
		block = &pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
		}
	case *ecdsa.PrivateKey:
		der, err := x509.MarshalECPrivateKey(privateKey)
		if err != nil {
			return nil, fmt.Errorf("marshal ECDSA private key: %w", err)
		}
		block = &pem.Block{Type: "EC PRIVATE KEY", Bytes: der}
	case ed25519.PrivateKey:
		der, err := x509.MarshalPKCS8PrivateKey(privateKey)
		if err != nil {
			return nil, fmt.Errorf("marshal Ed25519 private key: %w", err)
		}
		block = &pem.Block{Type: "PRIVATE KEY", Bytes: der}
	default:
		return nil, fmt.Errorf("unsupported CA private key type %T", ca.PrivateKey)
	}

	return pem.EncodeToMemory(block), nil
}

// LoadCAFromFiles reads and parses a PEM-encoded CA certificate and private key.
func LoadCAFromFiles(certFile, keyFile string) (*tls.Certificate, error) {
	certPEM, err := os.ReadFile(certFile)
	if err != nil {
		return nil, fmt.Errorf("read CA certificate file: %w", err)
	}

	keyPEM, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, fmt.Errorf("read CA private key file: %w", err)
	}

	ca, err := CAFromPEM(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("load CA files %q and %q: %w", certFile, keyFile, err)
	}
	return ca, nil
}

// SaveCA writes the CA certificate and private key with restrictive key permissions.
// New files are created exclusively, so an existing CA is never overwritten.
func SaveCA(ca *tls.Certificate, certFile, keyFile string) error {
	if certFile == keyFile {
		return errors.New("CA certificate and private key paths must differ")
	}

	certPEM := CACertPEM(ca)
	if len(certPEM) == 0 {
		return errors.New("CA certificate is unavailable")
	}
	keyPEM, err := CAKeyPEM(ca)
	if err != nil {
		return err
	}

	if err := os.MkdirAll(filepath.Dir(keyFile), 0o700); err != nil {
		return fmt.Errorf("create CA key directory: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(certFile), 0o700); err != nil {
		return fmt.Errorf("create CA certificate directory: %w", err)
	}

	if err := writeNewFile(keyFile, keyPEM, 0o600); err != nil {
		return fmt.Errorf("write CA private key: %w", err)
	}
	if err := writeNewFile(certFile, certPEM, 0o644); err != nil {
		_ = os.Remove(keyFile)
		return fmt.Errorf("write CA certificate: %w", err)
	}

	return nil
}

// LoadOrCreateCA loads a CA from certFile and keyFile, or generates and persists one.
func LoadOrCreateCA(certFile, keyFile string) (*tls.Certificate, error) {
	caLoadMu.Lock()
	defer caLoadMu.Unlock()

	ca, err := LoadCAFromFiles(certFile, keyFile)
	if err == nil {
		return ca, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}

	ca, err = GenerateCA()
	if err != nil {
		return nil, err
	}
	if err := SaveCA(ca, certFile, keyFile); err != nil {
		if errors.Is(err, os.ErrExist) {
			return LoadCAFromFiles(certFile, keyFile)
		}
		return nil, err
	}

	return ca, nil
}

// LoadOrCreateCertificate is an alias for LoadOrCreateCA.
func LoadOrCreateCertificate(certFile, keyFile string) (*tls.Certificate, error) {
	return LoadOrCreateCA(certFile, keyFile)
}

// InitCA is an alias for LoadOrCreateCA.
func InitCA(certFile, keyFile string) (*tls.Certificate, error) {
	return LoadOrCreateCA(certFile, keyFile)
}

// DefaultCAFilePaths returns the persisted CA paths for this user.
// GOPROXY_CA_CERT_FILE and GOPROXY_CA_KEY_FILE override the default location.
func DefaultCAFilePaths() (string, string, error) {
	certFile := os.Getenv("GOPROXY_CA_CERT_FILE")
	keyFile := os.Getenv("GOPROXY_CA_KEY_FILE")
	if certFile != "" || keyFile != "" {
		if certFile == "" || keyFile == "" {
			return "", "", errors.New("both GOPROXY_CA_CERT_FILE and GOPROXY_CA_KEY_FILE must be set")
		}
		return certFile, keyFile, nil
	}

	configDir, err := os.UserConfigDir()
	if err != nil {
		return "", "", fmt.Errorf("locate user configuration directory: %w", err)
	}

	caDir := filepath.Join(configDir, "goproxy")
	return filepath.Join(caDir, "ca.pem"), filepath.Join(caDir, "key.pem"), nil
}

// LoadOrCreateDefaultCA loads or creates the deployment's default persistent CA.
func LoadOrCreateDefaultCA() (*tls.Certificate, error) {
	certFile, keyFile, err := DefaultCAFilePaths()
	if err != nil {
		return nil, err
	}
	return LoadOrCreateCA(certFile, keyFile)
}

func writeNewFile(path string, data []byte, mode os.FileMode) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}

	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		_ = os.Remove(path)
		return err
	}
	if err := file.Close(); err != nil {
		_ = os.Remove(path)
		return err
	}
	if err := os.Chmod(path, mode); err != nil {
		_ = os.Remove(path)
		return err
	}
	return nil
}
