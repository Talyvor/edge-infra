package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// selfSignedCert writes a self-signed ECDSA cert+key pair to a temp dir and
// returns (certPath, keyPath, caPath) where caPath == certPath (self-signed).
func selfSignedCert(t *testing.T) (certPath, keyPath, caPath string) {
	t.Helper()
	dir := t.TempDir()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test-ca"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IsCA:         true,
		KeyUsage:     x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	require.NoError(t, err)

	certPath = filepath.Join(dir, "tls.crt")
	keyPath = filepath.Join(dir, "tls.key")

	certFile, err := os.Create(certPath)
	require.NoError(t, err)
	require.NoError(t, pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: der}))
	certFile.Close()

	keyFile, err := os.Create(keyPath)
	require.NoError(t, err)
	privDER, err := x509.MarshalECPrivateKey(priv)
	require.NoError(t, err)
	require.NoError(t, pem.Encode(keyFile, &pem.Block{Type: "EC PRIVATE KEY", Bytes: privDER}))
	keyFile.Close()

	return certPath, keyPath, certPath // ca == cert for self-signed
}

func TestBuildTLSCreds_NoCert_ReturnsNil(t *testing.T) {
	creds, err := buildTLSCreds("", "", "", true)
	require.NoError(t, err)
	assert.Nil(t, creds, "empty certFile must return nil creds (plaintext mode)")
}

func TestBuildTLSCreds_CertWithoutKey_Errors(t *testing.T) {
	_, err := buildTLSCreds("/some/cert.pem", "", "", true)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "XDS_TLS_KEY")
}

func TestBuildTLSCreds_ValidCertKey_ReturnsCreds(t *testing.T) {
	certPath, keyPath, _ := selfSignedCert(t)
	creds, err := buildTLSCreds(certPath, keyPath, "", true)
	require.NoError(t, err)
	require.NotNil(t, creds)
	assert.Equal(t, "tls", creds.Info().SecurityProtocol)
}

func TestBuildTLSCreds_BadCertFile_Errors(t *testing.T) {
	_, err := buildTLSCreds("/nonexistent/cert.pem", "/nonexistent/key.pem", "", true)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "load server keypair")
}

func TestBuildTLSCreds_WithCA_ReturnsMTLSCreds(t *testing.T) {
	certPath, keyPath, caPath := selfSignedCert(t)
	creds, err := buildTLSCreds(certPath, keyPath, caPath, false)
	require.NoError(t, err)
	require.NotNil(t, creds, "mTLS creds must not be nil")
	assert.Equal(t, "tls", creds.Info().SecurityProtocol)
}

func TestBuildTLSCreds_BadCAFile_Errors(t *testing.T) {
	certPath, keyPath, _ := selfSignedCert(t)
	_, err := buildTLSCreds(certPath, keyPath, "/nonexistent/ca.crt", false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "read CA file")
}

func TestBuildTLSCreds_WithoutMutualTLS_RefusedOutsideDevMode(t *testing.T) {
	certPath, keyPath, _ := selfSignedCert(t)
	for _, c := range [][3]string{{"", "", ""}, {certPath, keyPath, ""}} {
		_, err := buildTLSCreds(c[0], c[1], c[2], false)
		require.Error(t, err, "plaintext or server-only TLS must be refused without XDS_DEV_INSECURE")
		assert.Contains(t, err.Error(), "XDS_DEV_INSECURE")
	}
}
