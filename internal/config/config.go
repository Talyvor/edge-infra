package config

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"strconv"
	"time"
)

type Config struct {
	ListenAddr        string
	HealthAddr        string
	PostgresDSN       string
	NodeID            string
	ReconcileInterval time.Duration

	// Admin READ API (cmd/server's fourth listener; consumed by the suite BFF).
	// OPT-IN and fail-closed: the listener starts ONLY when AdminAPIKey is set —
	// unset means the surface does not exist. Read-only by design: it reports
	// state (including the effective ext_authz flag) and offers no way to change
	// anything.
	AdminAddr   string // XDS_ADMIN_ADDR (default :18002)
	AdminAPIKey string // XDS_ADMIN_API_KEY; empty ⇒ admin API disabled

	// HA — all optional. When RedisAddr is empty the server runs in
	// single-instance mode with local in-process state.
	RedisAddr     string
	RedisPassword string
	InstanceID    string // unique per replica; defaults to POD_NAME or a random ID

	TLSCertFile string
	TLSKeyFile  string
	TLSCAFile   string
	// DevInsecure (XDS_DEV_INSECURE=true) lets the xDS server run without mutual
	// TLS for local development; otherwise cert, key and client CA are required.
	DevInsecure bool

	// Gateway rate limiting (Envoy local_ratelimit, a per-listener token
	// bucket served via LDS). Fail-open by design: unlike auth, a limiter
	// problem must never block traffic. Per Envoy instance.
	RateLimitEnabled       bool
	RateLimitMaxTokens     uint32        // burst size
	RateLimitTokensPerFill uint32        // tokens added each fill interval
	RateLimitFillInterval  time.Duration // refill period (must be > 0)

	// Gateway ext_authz (Envoy → auth-service over gRPC). FAIL-CLOSED: if the
	// auth-service is unreachable Envoy denies. Opt-in, because enabling it
	// without a reachable auth-service denies all traffic suite-wide — flip it
	// on at cutover once the auth front is deployed and verified.
	ExtAuthzEnabled  bool
	ExtAuthzAddress  string // auth-service DNS name
	ExtAuthzPort     uint32
	ExtAuthzCAFile   string // upstream TLS trust CA (presence enables TLS)
	ExtAuthzCertFile string // upstream mTLS client cert (optional)
	ExtAuthzKeyFile  string // upstream mTLS client key (optional)

	// Gateway rate-limit service (Envoy global ratelimit → RLS over gRPC) —
	// the cross-instance, identity-keyed shared layer that further-restricts
	// the per-instance local_ratelimit floor. FAIL-OPEN: if the RLS is
	// unreachable Envoy allows (the floor still applies). Opt-in.
	RateLimitServiceEnabled  bool
	RateLimitServiceAddress  string
	RateLimitServicePort     uint32
	RateLimitServiceDomain   string
	RateLimitServiceCAFile   string
	RateLimitServiceCertFile string
	RateLimitServiceKeyFile  string

	// Gateway telemetry (Envoy → OpenTelemetry collector over OTLP/gRPC): every
	// listener's access log and trace spans. Opt-in; the stdout access log every
	// listener writes needs none of it. FAIL-OPEN: a missing collector loses
	// telemetry, never a request.
	TelemetryEnabled       bool
	TelemetryAddress       string  // collector DNS name
	TelemetryPort          uint32  // OTLP/gRPC port
	TelemetryServiceName   string  // service.name on spans and log records
	TelemetrySamplePercent float64 // share of requests traced, 0–100

	// Egress gateway (B28.222): the proxy listener edge-egress Envoys serve to
	// agents, reaching only the hosts in egress_destinations.
	EgressPort         uint32 // EGRESS_LISTENER_PORT
	EgressSystemCAFile string // EGRESS_SYSTEM_CA_FILE: trust store for a destination with no CA

	// B28.228: each agent's rate limit through edge-egress, and the decision log.
	EgressAgentRequestsPerMinute uint32 // EGRESS_AGENT_REQUESTS_PER_MINUTE: per agent, per edge-egress Envoy; 0 = no limit
	EgressDecisionLog            bool   // EGRESS_DECISION_LOG: record every edge-egress decision in edge_decisions

	// B28.238: the Talyvor Edge licence. Advisory — it is logged and exported as
	// edge_licence_valid, and no traffic depends on it.
	LicenceFile       string // EDGE_LICENCE_FILE: the installed licence token
	LicencePublicKeys string // EDGE_LICENCE_PUBLIC_KEYS: keys trusted beside Talyvor's, comma-separated base64
}

func FromEnv() (*Config, error) {
	c := &Config{
		ListenAddr:        getenv("XDS_LISTEN_ADDR", ":18000"),
		HealthAddr:        getenv("XDS_HEALTH_ADDR", ":18001"),
		PostgresDSN:       os.Getenv("POSTGRES_DSN"),
		NodeID:            getenv("XDS_NODE_ID", "edge-envoy"),
		ReconcileInterval: 5 * time.Second,
		RedisAddr:         os.Getenv("REDIS_ADDR"),
		RedisPassword:     os.Getenv("REDIS_PASSWORD"),
		InstanceID:        getenv("XDS_INSTANCE_ID", getenv("POD_NAME", randomID())),
		TLSCertFile:       os.Getenv("XDS_TLS_CERT"),
		TLSKeyFile:        os.Getenv("XDS_TLS_KEY"),
		TLSCAFile:         os.Getenv("XDS_TLS_CA"),
		DevInsecure:       os.Getenv("XDS_DEV_INSECURE") == "true",
		AdminAddr:         getenv("XDS_ADMIN_ADDR", ":18002"),
		AdminAPIKey:       os.Getenv("XDS_ADMIN_API_KEY"),
	}
	if c.PostgresDSN == "" {
		return nil, fmt.Errorf("POSTGRES_DSN is required")
	}
	if v := os.Getenv("XDS_RECONCILE_INTERVAL_MS"); v != "" {
		ms, err := strconv.Atoi(v)
		if err != nil {
			return nil, fmt.Errorf("XDS_RECONCILE_INTERVAL_MS: %w", err)
		}
		c.ReconcileInterval = time.Duration(ms) * time.Millisecond
	}

	c.RateLimitEnabled = getenvBool("GW_RATELIMIT_ENABLED", true)
	c.RateLimitMaxTokens = getenvU32("GW_RATELIMIT_MAX_TOKENS", 200)
	c.RateLimitTokensPerFill = getenvU32("GW_RATELIMIT_TOKENS_PER_FILL", 100)
	fillMS := getenvU32("GW_RATELIMIT_FILL_INTERVAL_MS", 1000)
	if fillMS == 0 {
		fillMS = 1000 // Envoy requires fill_interval > 0
	}
	c.RateLimitFillInterval = time.Duration(fillMS) * time.Millisecond

	c.ExtAuthzEnabled = getenvBool("EXT_AUTHZ_ENABLED", false)
	c.ExtAuthzAddress = getenv("EXT_AUTHZ_ADDRESS", "auth-service.infra.svc.cluster.local")
	c.ExtAuthzPort = getenvU32("EXT_AUTHZ_PORT", 50051)
	c.ExtAuthzCAFile = os.Getenv("EXT_AUTHZ_CA_FILE")
	c.ExtAuthzCertFile = os.Getenv("EXT_AUTHZ_CERT_FILE")
	c.ExtAuthzKeyFile = os.Getenv("EXT_AUTHZ_KEY_FILE")

	c.RateLimitServiceEnabled = getenvBool("RLS_ENABLED", false)
	c.RateLimitServiceAddress = getenv("RLS_ADDRESS", "ratelimit.infra.svc.cluster.local")
	c.RateLimitServicePort = getenvU32("RLS_PORT", 8082)
	c.RateLimitServiceDomain = getenv("RLS_DOMAIN", "edge")
	c.RateLimitServiceCAFile = os.Getenv("RLS_CA_FILE")
	c.RateLimitServiceCertFile = os.Getenv("RLS_CERT_FILE")
	c.RateLimitServiceKeyFile = os.Getenv("RLS_KEY_FILE")

	c.TelemetryEnabled = getenvBool("GW_OTEL_ENABLED", false)
	c.TelemetryAddress = getenv("GW_OTEL_COLLECTOR_ADDRESS", "otel-collector.monitoring.svc.cluster.local")
	c.TelemetryPort = getenvU32("GW_OTEL_COLLECTOR_PORT", 4317)
	c.TelemetryServiceName = getenv("GW_OTEL_SERVICE_NAME", "edge-proxy")
	c.TelemetrySamplePercent = 100
	if v := os.Getenv("GW_TRACE_SAMPLE_PERCENT"); v != "" {
		p, err := strconv.ParseFloat(v, 64)
		if err != nil || p < 0 || p > 100 {
			return nil, fmt.Errorf("GW_TRACE_SAMPLE_PERCENT: want a number from 0 to 100, got %q", v)
		}
		c.TelemetrySamplePercent = p
	}

	c.EgressPort = getenvU32("EGRESS_LISTENER_PORT", 3128)
	c.EgressSystemCAFile = getenv("EGRESS_SYSTEM_CA_FILE", "/etc/ssl/certs/ca-certificates.crt")
	c.EgressAgentRequestsPerMinute = getenvU32("EGRESS_AGENT_REQUESTS_PER_MINUTE", 0)
	c.EgressDecisionLog = getenvBool("EGRESS_DECISION_LOG", true)

	c.LicenceFile = getenv("EDGE_LICENCE_FILE", "/etc/edge-licence/licence")
	c.LicencePublicKeys = os.Getenv("EDGE_LICENCE_PUBLIC_KEYS")

	return c, nil
}

func getenvBool(k string, def bool) bool {
	v := os.Getenv(k)
	if v == "" {
		return def
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return def
	}
	return b
}

func getenvU32(k string, def uint32) uint32 {
	v := os.Getenv(k)
	if v == "" {
		return def
	}
	n, err := strconv.ParseUint(v, 10, 32)
	if err != nil {
		return def
	}
	return uint32(n)
}

func getenv(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func randomID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
