package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"

	"google.golang.org/grpc/credentials"
)

// buildTLSCreds constructs gRPC transport credentials from cert-manager-issued files.
// Outside devInsecure it requires certFile, keyFile and caFile: mutual TLS
// (RequireAndVerifyClientCert) is the only mode a deployment may run in. With
// devInsecure an empty certFile returns nil (plaintext) and an empty caFile
// gives server-only TLS.
func buildTLSCreds(certFile, keyFile, caFile string, devInsecure bool) (credentials.TransportCredentials, error) {
	if !devInsecure && (certFile == "" || caFile == "") {
		return nil, fmt.Errorf("XDS_TLS_CERT, XDS_TLS_KEY and XDS_TLS_CA are required (XDS_DEV_INSECURE=true allows plaintext for local development only)")
	}
	if certFile == "" {
		return nil, nil
	}
	if keyFile == "" {
		return nil, fmt.Errorf("XDS_TLS_KEY must be set when XDS_TLS_CERT is set")
	}

	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("load server keypair: %w", err)
	}

	cfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
	}

	if caFile != "" {
		pem, err := os.ReadFile(caFile)
		if err != nil {
			return nil, fmt.Errorf("read CA file: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("CA file contained no valid certificates: %s", caFile)
		}
		cfg.ClientCAs = pool
		cfg.ClientAuth = tls.RequireAndVerifyClientCert
	}

	return credentials.NewTLS(cfg), nil
}
