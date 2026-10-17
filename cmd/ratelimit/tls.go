package main

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"

	"google.golang.org/grpc/credentials"
)

// serverCreds builds the RLS's mutual-TLS credentials: only a client holding a
// certificate from caFile (Envoy's, from the edge internal CA) may connect.
// With devInsecure and no certFile it returns nil, and the server is plaintext.
func serverCreds(certFile, keyFile, caFile string, devInsecure bool) (credentials.TransportCredentials, error) {
	if devInsecure && certFile == "" {
		return nil, nil
	}
	if certFile == "" || keyFile == "" || caFile == "" {
		return nil, errors.New("RL_TLS_CERT, RL_TLS_KEY and RL_TLS_CA are required (RL_DEV_INSECURE=true allows plaintext for local development only)")
	}
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("load server keypair: %w", err)
	}
	pem, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("read CA file: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("CA file contained no valid certificates: %s", caFile)
	}
	return credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientCAs:    pool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		// Envoy's upstream TLS tops out at 1.2 unless the cluster pins tls_params.
		MinVersion: tls.VersionTLS12,
	}), nil
}
