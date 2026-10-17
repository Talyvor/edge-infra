package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	rlv3 "github.com/envoyproxy/go-control-plane/envoy/service/ratelimit/v3"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/edge-infra/control-plane/internal/ratelimit"
)

// issue signs a leaf for 127.0.0.1 with parent (self-signed CA when parent is nil).
func issue(t *testing.T, parent *x509.Certificate, parentKey *ecdsa.PrivateKey, isCA bool) (*x509.Certificate, *ecdsa.PrivateKey, []byte, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: "rls-test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  isCA,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}
	if parent == nil {
		parent, parentKey = tmpl, key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &key.PublicKey, parentKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	keyDER, _ := x509.MarshalECPrivateKey(key)
	return cert, key, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
}

func TestRateLimitServerRequiresMutualTLS(t *testing.T) {
	dir := t.TempDir()
	write := func(name string, b []byte) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, b, 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	ca, caKey, caPEM, _ := issue(t, nil, nil, true)
	_, _, srvPEM, srvKeyPEM := issue(t, ca, caKey, false)
	_, _, cliPEM, cliKeyPEM := issue(t, ca, caKey, false)

	if _, err := serverCreds("", "", "", false); err == nil {
		t.Fatal("without RL_DEV_INSECURE the server must refuse to start without mutual TLS")
	}
	creds, err := serverCreds(write("srv.crt", srvPEM), write("srv.key", srvKeyPEM), write("ca.crt", caPEM), false)
	if err != nil {
		t.Fatal(err)
	}
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := grpc.NewServer(grpc.Creds(creds))
	rlv3.RegisterRateLimitServiceServer(srv, ratelimit.NewService(ratelimit.New(nil), ratelimit.Rule{Capacity: 10, RatePerSec: 1}))
	go func() { _ = srv.Serve(lis) }()
	defer srv.Stop()

	call := func(c credentials.TransportCredentials) error {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		conn, err := grpc.NewClient(lis.Addr().String(), grpc.WithTransportCredentials(c))
		if err != nil {
			return err
		}
		defer conn.Close()
		_, err = rlv3.NewRateLimitServiceClient(conn).ShouldRateLimit(ctx, &rlv3.RateLimitRequest{Domain: "edge"})
		return err
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	clientPair, err := tls.X509KeyPair(cliPEM, cliKeyPEM)
	if err != nil {
		t.Fatal(err)
	}

	if err := call(insecure.NewCredentials()); err == nil {
		t.Error("a plaintext connection must be refused")
	}
	if err := call(credentials.NewTLS(&tls.Config{RootCAs: roots})); err == nil {
		t.Error("a TLS connection without a client certificate must be refused")
	}
	if err := call(credentials.NewTLS(&tls.Config{RootCAs: roots, Certificates: []tls.Certificate{clientPair}})); err != nil {
		t.Errorf("a client certificate from the CA must be served; got %v", err)
	}
}
