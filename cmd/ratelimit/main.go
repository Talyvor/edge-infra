// Command ratelimit is the Talyvor gateway rate-limit service (RLS). Envoy's
// global ratelimit filter calls it over gRPC with descriptors built from the
// route's rate_limit actions (x-user-id, remote_address); it answers OK or
// OVER_LIMIT from a Redis-backed token bucket that degrades to in-process on a
// Redis outage. It is the cross-instance shared layer that further-restricts
// the per-instance Envoy local_ratelimit floor.
package main

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	rlv3 "github.com/envoyproxy/go-control-plane/envoy/service/ratelimit/v3"
	"github.com/redis/go-redis/v9"
	"google.golang.org/grpc"

	"github.com/edge-infra/control-plane/internal/ratelimit"
)

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(log)
	if err := run(log); err != nil {
		log.Error("ratelimit exited with error", "err", err)
		os.Exit(1)
	}
}

func run(log *slog.Logger) error {
	listenAddr := getenv("RL_LISTEN_ADDR", ":8082")
	healthAddr := getenv("RL_HEALTH_ADDR", ":8083")
	rpm := getenvInt("RL_RPM", 60)
	burst := getenvInt("RL_BURST", rpm*3/2)

	var rdb *redis.Client
	if addr := os.Getenv("REDIS_ADDR"); addr != "" {
		rdb = redis.NewClient(&redis.Options{Addr: addr, Password: os.Getenv("REDIS_PASSWORD")})
		defer rdb.Close()
		log.Info("ratelimit: redis configured (cross-instance)", "addr", addr)
	} else {
		log.Warn("ratelimit: REDIS_ADDR unset — in-process limiting only (per instance)")
	}

	rule := ratelimit.Rule{Capacity: float64(burst), RatePerSec: float64(rpm) / 60.0}
	svc := ratelimit.NewService(ratelimit.New(rdb), rule)

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	creds, err := serverCreds(os.Getenv("RL_TLS_CERT"), os.Getenv("RL_TLS_KEY"), os.Getenv("RL_TLS_CA"), os.Getenv("RL_DEV_INSECURE") == "true")
	if err != nil {
		return err
	}
	var opts []grpc.ServerOption
	if creds != nil {
		opts = append(opts, grpc.Creds(creds))
	} else {
		log.Warn("RL_DEV_INSECURE: ratelimit gRPC running WITHOUT TLS — any client can connect")
	}

	lis, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return err
	}
	grpcSrv := grpc.NewServer(opts...)
	rlv3.RegisterRateLimitServiceServer(grpcSrv, svc)

	healthSrv := &http.Server{Addr: healthAddr, Handler: healthMux(), ReadHeaderTimeout: 10 * time.Second}

	errCh := make(chan error, 2)
	go func() {
		log.Info("ratelimit gRPC listening", "addr", listenAddr, "rpm", rpm, "burst", burst)
		errCh <- grpcSrv.Serve(lis)
	}()
	go func() {
		if err := healthSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	select {
	case <-ctx.Done():
		log.Info("shutdown signal received")
	case err := <-errCh:
		if err != nil && !errors.Is(err, grpc.ErrServerStopped) {
			grpcSrv.GracefulStop()
			return err
		}
	}

	grpcSrv.GracefulStop()
	shutCtx, c := context.WithTimeout(context.Background(), 10*time.Second)
	defer c()
	return healthSrv.Shutdown(shutCtx)
}

func healthMux() *http.ServeMux {
	mux := http.NewServeMux()
	ok := func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}
	mux.HandleFunc("/healthz", ok)
	mux.HandleFunc("/readyz", ok)
	return mux
}

func getenv(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func getenvInt(k string, def int) int {
	if v := os.Getenv(k); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}
