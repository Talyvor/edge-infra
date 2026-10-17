package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	accesslogservice "github.com/envoyproxy/go-control-plane/envoy/service/accesslog/v3"
	clusterservice "github.com/envoyproxy/go-control-plane/envoy/service/cluster/v3"
	discoverygrpc "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	endpointservice "github.com/envoyproxy/go-control-plane/envoy/service/endpoint/v3"
	listenerservice "github.com/envoyproxy/go-control-plane/envoy/service/listener/v3"
	routeservice "github.com/envoyproxy/go-control-plane/envoy/service/route/v3"
	runtimeservice "github.com/envoyproxy/go-control-plane/envoy/service/runtime/v3"
	secretservice "github.com/envoyproxy/go-control-plane/envoy/service/secret/v3"
	cachev3 "github.com/envoyproxy/go-control-plane/pkg/cache/v3"
	serverv3 "github.com/envoyproxy/go-control-plane/pkg/server/v3"
	"github.com/redis/go-redis/v9"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"

	"github.com/edge-infra/control-plane/internal/config"
	"github.com/edge-infra/control-plane/internal/decisions"
	"github.com/edge-infra/control-plane/internal/ha"
	"github.com/edge-infra/control-plane/internal/keycrypt"
	"github.com/edge-infra/control-plane/internal/licence"
	"github.com/edge-infra/control-plane/internal/store"
	"github.com/edge-infra/control-plane/internal/xds"
	"github.com/edge-infra/control-plane/internal/xds/builders"
)

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(log)

	if err := run(log); err != nil {
		log.Error("server exited with error", "err", err)
		os.Exit(1)
	}
}

func run(log *slog.Logger) error {
	cfg, err := config.FromEnv()
	if err != nil {
		return err
	}

	rootCtx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	// Optional at-rest decryption key for SDS secret keys (must match the
	// custodian's SECRET_KEK). Empty ⇒ plaintext keys; a sealed key read without
	// it fails loudly at snapshot load (fail-closed). During a KEK rotation
	// SECRET_KEK_PREVIOUS (comma-separated) holds the old KEKs, so keys not yet
	// re-sealed still open.
	ring, err := keycrypt.ParseKeyring(os.Getenv("SECRET_KEK"), os.Getenv("SECRET_KEK_PREVIOUS"))
	if err != nil {
		return fmt.Errorf("SECRET_KEK / SECRET_KEK_PREVIOUS: %w", err)
	}

	licenceKeys, err := licence.TrustedKeys(cfg.LicencePublicKeys)
	if err != nil {
		log.Warn("EDGE_LICENCE_PUBLIC_KEYS: a key was ignored", "err", err)
	}

	pgCtx, pgCancel := context.WithTimeout(rootCtx, 10*time.Second)
	pgStore, err := store.NewPostgresStore(pgCtx, cfg.PostgresDSN, store.WithKeyring(ring))
	pgCancel()
	if err != nil {
		return err
	}
	defer pgStore.Close()

	// R4 co-location invariant (fail-closed): the control-plane and OSB MUST share
	// one database. Refuse to start if the configured DB is missing either the
	// control-plane or the OSB schema — a divergent DSN is a misconfiguration, not
	// a runtime state.
	coCtx, coCancel := context.WithTimeout(rootCtx, 10*time.Second)
	err = pgStore.VerifyColocation(coCtx)
	coCancel()
	if err != nil {
		return fmt.Errorf("co-location self-check: %w", err)
	}

	cache := cachev3.NewSnapshotCache(true, cachev3.IDHash{}, slogCacheLogger{log: log})
	reconciler := xds.NewReconciler(cache, pgStore, cfg.NodeID, log)
	reconciler.WithRateLimit(builders.RateLimitOptions{
		Enabled:       cfg.RateLimitEnabled,
		MaxTokens:     cfg.RateLimitMaxTokens,
		TokensPerFill: cfg.RateLimitTokensPerFill,
		FillInterval:  cfg.RateLimitFillInterval,
	})
	reconciler.WithExtAuthz(builders.ExtAuthzOptions{
		Enabled:  cfg.ExtAuthzEnabled,
		Address:  cfg.ExtAuthzAddress,
		Port:     cfg.ExtAuthzPort,
		CAFile:   cfg.ExtAuthzCAFile,
		CertFile: cfg.ExtAuthzCertFile,
		KeyFile:  cfg.ExtAuthzKeyFile,
	})
	reconciler.WithRateLimitService(builders.RateLimitServiceOptions{
		Enabled:  cfg.RateLimitServiceEnabled,
		Address:  cfg.RateLimitServiceAddress,
		Port:     cfg.RateLimitServicePort,
		Domain:   cfg.RateLimitServiceDomain,
		CAFile:   cfg.RateLimitServiceCAFile,
		CertFile: cfg.RateLimitServiceCertFile,
		KeyFile:  cfg.RateLimitServiceKeyFile,
	})
	reconciler.WithTelemetry(builders.TelemetryOptions{
		Enabled:       cfg.TelemetryEnabled,
		Address:       cfg.TelemetryAddress,
		Port:          cfg.TelemetryPort,
		ServiceName:   cfg.TelemetryServiceName,
		SamplePercent: cfg.TelemetrySamplePercent,
	})
	reconciler.WithEgress(builders.EgressOptions{
		Port:                   cfg.EgressPort,
		SystemCAFile:           cfg.EgressSystemCAFile,
		AgentRequestsPerMinute: cfg.EgressAgentRequestsPerMinute,
		DecisionLog:            cfg.EgressDecisionLog,
	})

	// HA mode: wire Redis coordinator when REDIS_ADDR is configured.
	if cfg.RedisAddr != "" {
		rdb := redis.NewClient(&redis.Options{
			Addr:     cfg.RedisAddr,
			Password: cfg.RedisPassword,
		})
		coord := ha.NewRedisCoordinator(rdb, cfg.InstanceID)
		reconciler.WithCoordinator(coord)
		log.Info("ha: Redis coordinator enabled",
			"addr", cfg.RedisAddr,
			"instance_id", cfg.InstanceID,
		)
		go coord.Run(rootCtx, log)
	} else {
		log.Info("ha: running in single-instance mode (set REDIS_ADDR to enable HA)")
	}

	tlsCreds, err := buildTLSCreds(cfg.TLSCertFile, cfg.TLSKeyFile, cfg.TLSCAFile, cfg.DevInsecure)
	if err != nil {
		return fmt.Errorf("tls config: %w", err)
	}
	mtls := tlsCreds != nil && cfg.TLSCAFile != ""
	if !mtls {
		log.Warn("XDS_DEV_INSECURE: xDS gRPC running WITHOUT mutual TLS — any client can claim any node id")
	}

	callbacks := &onConnectCallbacks{
		reconciler: reconciler,
		cache:      cache,
		log:        log,
	}

	xdsSrv := serverv3.NewServer(rootCtx, cache, callbacks)
	grpcSrv := newGRPCServer(tlsCreds, mtls)
	registerXDS(grpcSrv, xdsSrv)
	// edge-egress's decision log (B28.228) arrives on the same listener, from
	// Envoys holding an xDS client certificate. Without TLS anyone who can reach
	// the port could write to it, so it is not served at all.
	if tlsCreds != nil {
		accesslogservice.RegisterAccessLogServiceServer(grpcSrv, decisions.NewService(pgStore, xds.IsEgressNode, log))
	} else {
		log.Warn("decision log NOT served: it needs xDS TLS")
	}

	lis, err := net.Listen("tcp", cfg.ListenAddr)
	if err != nil {
		return err
	}

	// Buffered for all long-lived goroutines (gRPC, reconciler, health, metrics,
	// admin) so each can report its exit without blocking even when the select
	// below has already returned on another's error or on shutdown.
	errCh := make(chan error, 5)
	go func() {
		log.Info("xds gRPC listening", "addr", cfg.ListenAddr, "node_id", cfg.NodeID)
		errCh <- grpcSrv.Serve(lis)
	}()
	go func() {
		errCh <- reconciler.Run(rootCtx, cfg.ReconcileInterval)
	}()

	// Health/readiness HTTP server (additive; read-only view of the xDS cache).
	healthSrv := newHealthServer(cfg.HealthAddr, cache, cfg.NodeID)
	go func() {
		errCh <- runHealthServer(rootCtx, healthSrv, log)
	}()

	// The Talyvor Edge licence (B28.238): checked offline, logged on every change
	// and exported as edge_licence_valid. Advisory — nothing above depends on it,
	// so an expired or missing licence never drops traffic.
	lic := licence.NewWatcher(cfg.LicenceFile, licenceKeys, log)
	go lic.Run(rootCtx, time.Minute)

	// Metrics HTTP server (additive; read-only view of the reconciler's
	// fail-static guard counters). Exposes xds_snapshots_blocked_total on :2112 —
	// the port the edge-control-plane chart already declares and scrapes — so prod
	// can alert on withheld snapshots.
	metricsSrv := newMetricsServer(metricsAddr, xds.NewMetricsHandler(reconciler, lic))
	go func() {
		errCh <- runMetricsServer(rootCtx, metricsSrv, log)
	}()

	// Admin READ API (fourth listener; consumed by the suite BFF). OPT-IN and
	// fail-closed: without XDS_ADMIN_API_KEY the surface does not exist at all.
	// Read-only by design — see admin.go. Uses the same pgStore (its key-free
	// admin readers never touch key_pem) and the reconciler's read-only
	// observability accessors.
	if cfg.AdminAPIKey != "" {
		adminSrv := newAdminServer(cfg.AdminAddr, adminDeps{
			store: pgStore,
			nodes: reconciler,
			cfg:   newAdminConfigView(cfg),
			key:   cfg.AdminAPIKey,
			log:   log,
		})
		go func() {
			errCh <- runAdminServer(rootCtx, adminSrv, log)
		}()
	} else {
		log.Info("admin API disabled (XDS_ADMIN_API_KEY unset)")
	}

	select {
	case <-rootCtx.Done():
		log.Info("shutdown signal received")
	case err := <-errCh:
		if err != nil && !errors.Is(err, context.Canceled) {
			cancel()
			grpcSrv.GracefulStop()
			return err
		}
	}

	grpcSrv.GracefulStop()
	return nil
}

// newGRPCServer builds the xDS gRPC server. bindNodes refuses every request whose
// node id the client certificate does not speak for (see nodeauth.go).
func newGRPCServer(creds credentials.TransportCredentials, bindNodes bool) *grpc.Server {
	opts := []grpc.ServerOption{
		grpc.KeepaliveParams(keepalive.ServerParameters{
			MaxConnectionIdle:     5 * time.Minute,
			MaxConnectionAge:      30 * time.Minute,
			MaxConnectionAgeGrace: 5 * time.Minute,
			Time:                  30 * time.Second,
			Timeout:               10 * time.Second,
		}),
		grpc.KeepaliveEnforcementPolicy(keepalive.EnforcementPolicy{
			MinTime:             10 * time.Second,
			PermitWithoutStream: true,
		}),
	}
	if creds != nil {
		opts = append(opts, grpc.Creds(creds))
	}
	if bindNodes {
		opts = append(opts, grpc.UnaryInterceptor(nodeIdentityUnary), grpc.StreamInterceptor(nodeIdentityStream))
	}
	return grpc.NewServer(opts...)
}

func registerXDS(s *grpc.Server, x serverv3.Server) {
	discoverygrpc.RegisterAggregatedDiscoveryServiceServer(s, x)
	clusterservice.RegisterClusterDiscoveryServiceServer(s, x)
	endpointservice.RegisterEndpointDiscoveryServiceServer(s, x)
	listenerservice.RegisterListenerDiscoveryServiceServer(s, x)
	routeservice.RegisterRouteDiscoveryServiceServer(s, x)
	secretservice.RegisterSecretDiscoveryServiceServer(s, x)
	runtimeservice.RegisterRuntimeDiscoveryServiceServer(s, x)
}

type slogCacheLogger struct {
	log *slog.Logger
}

func (l slogCacheLogger) Debugf(format string, args ...interface{}) {
	l.log.Debug("xds-cache", "msg", sprintf(format, args...))
}
func (l slogCacheLogger) Infof(format string, args ...interface{}) {
	l.log.Info("xds-cache", "msg", sprintf(format, args...))
}
func (l slogCacheLogger) Warnf(format string, args ...interface{}) {
	l.log.Warn("xds-cache", "msg", sprintf(format, args...))
}
func (l slogCacheLogger) Errorf(format string, args ...interface{}) {
	l.log.Error("xds-cache", "msg", sprintf(format, args...))
}

func sprintf(format string, args ...interface{}) string {
	if len(args) == 0 {
		return format
	}
	return fmt.Sprintf(format, args...)
}
