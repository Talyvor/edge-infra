//go:build integration

// Real-Envoy xDS TLS-version regression test (F10).
//
// The Go-only TestXDSMutualTLSHandshake cannot catch this class: its client
// hardcodes MinVersion TLS 1.3, so it always negotiates 1.3 with the server.
// A REAL Envoy's BoringSSL upstream defaults its MAXIMUM TLS version to 1.2
// unless tls_params pins 1.3 — and the control-plane xDS server requires
// MinVersion 1.3 (buildTLSCreds). Result in prod: the proxy's xDS handshake
// fails and it never receives config. This test stands up the REAL buildTLSCreds
// server and runs an ACTUAL envoyproxy/envoy against it, proving:
//   - WITHOUT tls_params → the handshake FAILS (0 ssl.handshake) — the bug.
//   - WITH    tls_params (as the edge-proxy chart now ships) → it SUCCEEDS.
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	clusterv3 "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	"github.com/envoyproxy/go-control-plane/pkg/cache/types"
	cachev3 "github.com/envoyproxy/go-control-plane/pkg/cache/v3"
	resourcev3 "github.com/envoyproxy/go-control-plane/pkg/resource/v3"
	serverv3 "github.com/envoyproxy/go-control-plane/pkg/server/v3"
	"google.golang.org/grpc"
)

const envoyImage = "envoyproxy/envoy:v1.39.2@sha256:460f8c329f24b2e1c7c5af64cb314a6f351ad1c262ba77b135ac46b35ebd5f85"

func TestXDSRealEnvoyTLSVersion(t *testing.T) {
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker required for the real-Envoy xDS TLS test")
	}
	dir := t.TempDir()
	ca := newTestCA(t)
	serverPair := ca.issue(t, xdsServerSAN, true)
	clientPair := ca.issue(t, "edge-proxy", false)

	// Server keypair → the REAL buildTLSCreds (MinVersion 1.3, RequireAndVerify).
	srvCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: serverPair.Certificate[0]})
	srvKeyDER, _ := x509.MarshalECPrivateKey(serverPair.PrivateKey.(*ecdsa.PrivateKey))
	srvKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: srvKeyDER})
	writeTemp(t, dir, "ca.crt", ca.certPEM) // Envoy's trusted_ca
	// Server-auth TLS only: this test isolates the F10 TLS-VERSION dimension (the
	// bug is version negotiation, orthogonal to mTLS). Client-cert verification is
	// covered by TestXDSMutualTLSHandshake and the in-cluster cutover proof.
	creds, err := buildTLSCreds(
		writeTemp(t, dir, "server.crt", srvCertPEM),
		writeTemp(t, dir, "server.key", srvKeyPEM),
		"", true, // server-only TLS is a dev-mode configuration
	)
	if err != nil {
		t.Fatalf("buildTLSCreds: %v", err)
	}

	// Client keypair + CA, mounted into the Envoy container.
	cliCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: clientPair.Certificate[0]})
	cliKeyDER, _ := x509.MarshalECPrivateKey(clientPair.PrivateKey.(*ecdsa.PrivateKey))
	writeTemp(t, dir, "client.crt", cliCertPEM)
	writeTemp(t, dir, "client.key", pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: cliKeyDER}))

	// Real ADS server on all interfaces (reachable from the Envoy container).
	lis, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	cache := cachev3.NewSnapshotCache(false, cachev3.IDHash{}, nil)
	snap, _ := cachev3.NewSnapshot("1", map[resourcev3.Type][]types.Resource{
		resourcev3.ClusterType: {&clusterv3.Cluster{Name: "seeded-cluster"}},
	})
	_ = cache.SetSnapshot(context.Background(), "test-node", snap)
	grpcSrv := grpc.NewServer(grpc.Creds(creds))
	registerXDS(grpcSrv, serverv3.NewServer(context.Background(), cache, nil))
	go func() { _ = grpcSrv.Serve(lis) }()
	defer grpcSrv.Stop()
	port := lis.Addr().(*net.TCPAddr).Port

	// runEnvoy starts a real Envoy with/without tls_params and returns its
	// cluster.xds_cluster.ssl.handshake count after giving it time to connect.
	runEnvoy := func(t *testing.T, withTLSParams bool) int {
		t.Helper()
		linux := runtime.GOOS == "linux"
		hostAddr := "host.docker.internal" // Docker Desktop reaches the host here
		if linux {
			hostAddr = "127.0.0.1" // with --network host, Envoy shares the runner net
		}
		params := ""
		if withTLSParams {
			params = "tls_params: { tls_minimum_protocol_version: TLSv1_2, tls_maximum_protocol_version: TLSv1_3 }\n          " // 10-space indent to align with validation_context
		}
		bootstrap := fmt.Sprintf(`
admin: { address: { socket_address: { address: 0.0.0.0, port_value: 9901 } } }
node: { id: test-node, cluster: edge-proxy }
dynamic_resources:
  ads_config:
    api_type: GRPC
    transport_api_version: V3
    grpc_services: [{ envoy_grpc: { cluster_name: xds_cluster } }]
  cds_config: { ads: {}, resource_api_version: V3 }
  lds_config: { ads: {}, resource_api_version: V3 }
static_resources:
  clusters:
  - name: xds_cluster
    connect_timeout: 3s
    type: STRICT_DNS
    typed_extension_protocol_options:
      envoy.extensions.upstreams.http.v3.HttpProtocolOptions:
        "@type": type.googleapis.com/envoy.extensions.upstreams.http.v3.HttpProtocolOptions
        explicit_http_config: { http2_protocol_options: {} }
    load_assignment:
      cluster_name: xds_cluster
      endpoints: [{ lb_endpoints: [{ endpoint: { address: { socket_address: { address: %s, port_value: %d } } } }] }]
    transport_socket:
      name: envoy.transport_sockets.tls
      typed_config:
        "@type": type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.UpstreamTlsContext
        sni: %s
        common_tls_context:
          %svalidation_context:
            trusted_ca: { filename: /certs/ca.crt }
            match_typed_subject_alt_names: [{ san_type: DNS, matcher: { exact: %s } }]
`, hostAddr, port, xdsServerSAN, params, xdsServerSAN)
		bootName := "bootstrap-noparams.yaml"
		if withTLSParams {
			bootName = "bootstrap-params.yaml"
		}
		writeTemp(t, dir, bootName, []byte(bootstrap))
		// The envoy container runs non-root (uid 101); writeTemp uses 0600, so under
		// strict Linux uids envoy can't read the mounted certs/bootstrap ("unable to
		// read file"). Docker Desktop's loose fs hides this on macOS. Make them
		// world-readable (and the dir traversable).
		_ = exec.Command("chmod", "-R", "a+rX", dir).Run()

		name := "xds-tls-test-" + strconv.Itoa(port) + map[bool]string{true: "-p", false: "-n"}[withTLSParams]
		_ = exec.Command("docker", "rm", "-f", name).Run()
		args := []string{"run", "-d", "--name", name, "-v", dir + ":/certs:ro"}
		statsURL := "" // set below per platform (envoy image has no wget/curl → scrape from the host)
		if linux {
			// Share the runner's network namespace so Envoy reaches the in-test
			// server on 127.0.0.1 and its admin is directly queryable. (host.docker.
			// internal via the bridge gateway is unreliable on CI runners.)
			args = append(args, "--network", "host")
			statsURL = "http://127.0.0.1:9901/stats?filter=cluster.xds_cluster.ssl.handshake"
		} else {
			// Docker Desktop: publish the admin port (envoy does not EXPOSE 9901).
			args = append(args, "-p", "127.0.0.1::9901")
		}
		args = append(args, envoyImage, "-c", "/certs/"+bootName, "-l", "warning")
		out, err := exec.Command("docker", args...).CombinedOutput()
		if err != nil {
			t.Fatalf("docker run envoy: %v\n%s", err, out)
		}
		// Remove at the END of this run (not test end) so sequential --network host
		// runs don't collide on the admin port.
		defer func() { _ = exec.Command("docker", "rm", "-f", name).Run() }()

		if !linux {
			pout, _ := exec.Command("docker", "port", name, "9901").CombinedOutput()
			adminHostPort := strings.TrimSpace(string(pout))
			if i := strings.LastIndex(adminHostPort, ":"); i >= 0 {
				adminHostPort = adminHostPort[i+1:]
			}
			statsURL = "http://127.0.0.1:" + adminHostPort + "/stats?filter=cluster.xds_cluster.ssl.handshake"
		}

		// Poll ssl.handshake for up to ~20s.
		var handshake int
		for i := 0; i < 20; i++ {
			time.Sleep(1 * time.Second)
			resp, err := http.Get(statsURL)
			if err != nil {
				continue
			}
			body, _ := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			for _, line := range strings.Split(string(body), "\n") {
				if strings.Contains(line, "ssl.handshake:") {
					handshake, _ = strconv.Atoi(strings.TrimSpace(line[strings.LastIndex(line, ":")+1:]))
				}
			}
			if handshake > 0 {
				break
			}
		}
		if handshake == 0 {
			logs, _ := exec.Command("docker", "logs", "--tail", "20", name).CombinedOutput()
			var full []byte
			if resp, e := http.Get(strings.Replace(statsURL, ".ssl.handshake", "", 1)); e == nil {
				full, _ = io.ReadAll(resp.Body)
				_ = resp.Body.Close()
			}
			t.Logf("[diag withTLSParams=%v] envoy logs:\n%s\n--- xds_cluster stats ---\n%s", withTLSParams, logs, full)
		}
		return handshake
	}

	// GREEN (guards the fix): with tls_params — as the edge-proxy chart ships — a
	// real Envoy completes the xDS TLS handshake against the TLS-1.3-min server.
	// This doubles as the harness self-check: if a real-Envoy xDS connection can't
	// be established in THIS environment (e.g. macOS Docker host-networking to an
	// ephemeral-port test server), skip rather than false-fail — the assertion is
	// meaningful only where the harness can connect (Linux CI).
	if runEnvoy(t, true) == 0 {
		t.Fatal("real Envoy did NOT complete the xDS handshake WITH tls_params — the fix regressed or the harness broke")
	}

	// RED (the F10 bug): WITHOUT tls_params, the same real Envoy caps its upstream
	// at TLS 1.2 and CANNOT handshake with the 1.3-min server — it would never
	// receive config.
	if noParams := runEnvoy(t, false); noParams != 0 {
		t.Errorf("without tls_params the real Envoy must NOT complete the xDS handshake "+
			"(Envoy max TLS 1.2 vs server min 1.3); got %d handshakes", noParams)
	}
}
