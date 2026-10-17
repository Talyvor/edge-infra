//go:build integration

// Live xDS mutual-TLS handshake validation (closes R1's deferral as built work).
// Stands up the real ADS gRPC server with buildTLSCreds (RequireAndVerifyClient-
// Cert) against an in-memory edge-internal-ca, then asserts: a valid client cert
// completes the handshake AND receives a snapshot; a client with NO cert, or a
// cert from the WRONG CA, fails the handshake (fail-closed). No DB/Docker — it
// runs anywhere with `-tags integration`.
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

	clusterv3 "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	discoverygrpc "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	"github.com/envoyproxy/go-control-plane/pkg/cache/types"
	cachev3 "github.com/envoyproxy/go-control-plane/pkg/cache/v3"
	resourcev3 "github.com/envoyproxy/go-control-plane/pkg/resource/v3"
	serverv3 "github.com/envoyproxy/go-control-plane/pkg/server/v3"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"
)

const xdsServerSAN = "edge-control-plane"

type testCA struct {
	cert    *x509.Certificate
	key     *ecdsa.PrivateKey
	certPEM []byte
}

func newTestCA(t *testing.T) *testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "edge-internal-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	return &testCA{cert: cert, key: key, certPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}
}

// issue signs a leaf keypair; server certs carry the SAN + serverAuth, clients
// carry clientAuth.
func (ca *testCA) issue(t *testing.T, cn string, server bool) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	if server {
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		tmpl.DNSNames = []string{xdsServerSAN, "localhost"}
		tmpl.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
	} else {
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
		tmpl.DNSNames = []string{cn} // the identity certAllowsNode reads
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, _ := x509.MarshalECPrivateKey(key)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	return pair
}

func writeTemp(t *testing.T, dir, name string, data []byte) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func poolOf(pemBytes []byte) *x509.CertPool {
	p := x509.NewCertPool()
	p.AppendCertsFromPEM(pemBytes)
	return p
}

func TestXDSMutualTLSHandshake(t *testing.T) {
	dir := t.TempDir()
	ca := newTestCA(t) // the edge-internal-ca
	serverPair := ca.issue(t, xdsServerSAN, true)
	clientPair := ca.issue(t, proxyClientIdentity, false)  // valid client, signed by the CA
	egressPair := ca.issue(t, egressClientIdentity, false) // valid, but not for a proxy node
	otherNodePair := ca.issue(t, "other-node", false)      // valid, but for another node
	wrongCA := newTestCA(t)                                // a different CA
	wrongPair := wrongCA.issue(t, "attacker", false)

	// Write the server keypair + CA to disk so we exercise the REAL buildTLSCreds.
	srvCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: serverPair.Certificate[0]})
	srvKeyDER, _ := x509.MarshalECPrivateKey(serverPair.PrivateKey.(*ecdsa.PrivateKey))
	srvKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: srvKeyDER})
	certFile := writeTemp(t, dir, "server.crt", srvCertPEM)
	keyFile := writeTemp(t, dir, "server.key", srvKeyPEM)
	caFile := writeTemp(t, dir, "ca.crt", ca.certPEM)

	creds, err := buildTLSCreds(certFile, keyFile, caFile, false)
	if err != nil {
		t.Fatalf("buildTLSCreds: %v", err)
	}
	if creds == nil {
		t.Fatal("expected mTLS creds, got nil")
	}

	// Real ADS server with a seeded snapshot.
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	cache := cachev3.NewSnapshotCache(false, cachev3.IDHash{}, nil)
	snap, err := cachev3.NewSnapshot("1", map[resourcev3.Type][]types.Resource{
		resourcev3.ClusterType: {&clusterv3.Cluster{Name: "test-cluster"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := cache.SetSnapshot(context.Background(), "test-node", snap); err != nil {
		t.Fatal(err)
	}
	grpcSrv := newGRPCServer(creds, true)
	registerXDS(grpcSrv, serverv3.NewServer(context.Background(), cache, nil))
	go func() { _ = grpcSrv.Serve(lis) }()
	defer grpcSrv.Stop()
	addr := lis.Addr().String()

	// dialAndStream opens an ADS stream and requests the seeded cluster, returning
	// the first error (handshake or stream). nil means the snapshot was received.
	dialAndStream := func(clientTLS *tls.Config, nodeID string) error {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		conn, err := grpc.DialContext(ctx, addr,
			grpc.WithTransportCredentials(credentials.NewTLS(clientTLS)),
			grpc.WithBlock(), grpc.FailOnNonTempDialError(true))
		if err != nil {
			return err
		}
		defer conn.Close()
		stream, err := discoverygrpc.NewAggregatedDiscoveryServiceClient(conn).StreamAggregatedResources(ctx)
		if err != nil {
			return err
		}
		if err := stream.Send(&discoverygrpc.DiscoveryRequest{
			TypeUrl: resourcev3.ClusterType,
			Node:    &corev3.Node{Id: nodeID},
		}); err != nil {
			return err
		}
		_, err = stream.Recv()
		return err
	}

	base := func() *tls.Config {
		return &tls.Config{RootCAs: poolOf(ca.certPEM), ServerName: xdsServerSAN, MinVersion: tls.VersionTLS13}
	}

	t.Run("valid client cert completes handshake and receives a snapshot", func(t *testing.T) {
		c := base()
		c.Certificates = []tls.Certificate{clientPair}
		if err := dialAndStream(c, "test-node"); err != nil {
			t.Errorf("valid mTLS client must succeed; got %v", err)
		}
	})

	for name, pair := range map[string]tls.Certificate{
		"a certificate for another node": otherNodePair,
		"an egress certificate":          egressPair,
	} {
		t.Run(name+" receives no snapshot for test-node", func(t *testing.T) {
			c := base()
			c.Certificates = []tls.Certificate{pair}
			if err := dialAndStream(c, "test-node"); status.Code(err) != codes.PermissionDenied {
				t.Errorf("a certificate that does not speak for the node must be refused before any snapshot; got %v", err)
			}
		})
	}

	t.Run("an egress certificate is served as an egress node", func(t *testing.T) {
		c := base()
		c.Certificates = []tls.Certificate{egressPair}
		if err := dialAndStream(c, "edge-egress/pod-1"); status.Code(err) == codes.PermissionDenied {
			t.Errorf("an egress certificate must speak for an egress node; got %v", err)
		}
	})

	t.Run("no client cert fails closed", func(t *testing.T) {
		if err := dialAndStream(base(), "test-node"); err == nil {
			t.Error("a client with NO cert must fail the mTLS handshake (fail-closed)")
		}
	})

	t.Run("wrong-CA client cert fails closed", func(t *testing.T) {
		c := base()
		c.Certificates = []tls.Certificate{wrongPair}
		if err := dialAndStream(c, "test-node"); err == nil {
			t.Error("a client cert from the WRONG CA must fail the mTLS handshake (fail-closed)")
		}
	})
}
