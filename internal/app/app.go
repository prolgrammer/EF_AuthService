package app

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"go.uber.org/zap"
	"golang.org/x/sync/errgroup"

	"github.com/eventflow/auth-service/internal/config"
	"github.com/eventflow/auth-service/internal/keystore"
	"github.com/eventflow/auth-service/internal/logger"
	"github.com/eventflow/auth-service/internal/observability"
	pgrepo "github.com/eventflow/auth-service/internal/repository/postgres"
	authsvc "github.com/eventflow/auth-service/internal/service/auth"
	"github.com/eventflow/auth-service/internal/transport/grpcsrv"
	"github.com/eventflow/auth-service/internal/transport/httpsrv"
)

// Run — entrypoint, вызывается из main.
//
// Порядок:
//  1. Config & Logger.
//  2. Observability (metrics, tracing).
//  3. Postgres + миграции.
//  4. Keystore + JWT issuer.
//  5. Сервис auth.
//  6. HTTP / gRPC / Metrics-серверы — в errgroup.
//  7. Ожидание сигнала, graceful shutdown с общим таймаутом.
func Run(ctx context.Context) error {
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("config: %w", err)
	}

	log, err := logger.New(string(cfg.Env), cfg.LogLevel, "auth-service", cfg.InstanceID)
	if err != nil {
		return fmt.Errorf("logger: %w", err)
	}
	defer func() { _ = log.Sync() }()

	log.Info("auth-service starting",
		zap.String("env", string(cfg.Env)),
		zap.String("instance_id", cfg.InstanceID),
	)

	// --- observability ---
	metrics := observability.NewMetrics()
	traceShutdown, err := observability.InitTracing(ctx, observability.TracingConfig{
		Enabled:     cfg.Tracing.Enabled,
		Endpoint:    cfg.Tracing.OTLPEndpoint,
		ServiceName: "auth-service",
		Instance:    cfg.InstanceID,
		SampleRatio: cfg.Tracing.SampleRatio,
		Env:         string(cfg.Env),
	})
	if err != nil {
		return fmt.Errorf("tracing: %w", err)
	}
	defer func() {
		shCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = traceShutdown(shCtx)
	}()

	// --- postgres ---
	pool, err := pgrepo.Connect(ctx, cfg.DB.DSN, cfg.DB.MaxConns, cfg.DB.MinConns)
	if err != nil {
		return fmt.Errorf("db: %w", err)
	}
	defer pool.Close()

	if cfg.DB.MigrateOnStart {
		if err := pgrepo.Migrate(ctx, pool, cfg.DB.MigrationsDir); err != nil {
			return fmt.Errorf("migrate: %w", err)
		}
		log.Info("db migrations applied", zap.String("dir", cfg.DB.MigrationsDir))
	}

	users := pgrepo.NewUserRepo(pool)
	tokens := pgrepo.NewRefreshTokenRepo(pool)

	// --- keystore + jwt ---
	ks, err := keystore.New(keystore.Options{
		Dir:         cfg.JWT.KeyDir,
		RotateEvery: cfg.JWT.RotateEvery,
		OverlapFor:  cfg.JWT.OverlapFor,
		Logger:      log.Named("keystore"),
		OnRotate:    func() { metrics.KeyRotations.Inc() },
		SetGauge:    func(n int) { metrics.ActiveJWKKeys.Set(float64(n)) },
	})
	if err != nil {
		return fmt.Errorf("keystore: %w", err)
	}
	jwtIssuer := authsvc.NewJWTIssuer(ks, cfg.JWT.Issuer, cfg.JWT.AccessTTL, cfg.JWT.RefreshTTL)

	// --- service ---
	svc := authsvc.New(authsvc.Options{
		Users:   users,
		Tokens:  tokens,
		JWT:     jwtIssuer,
		Logger:  log.Named("auth"),
		Metrics: metrics,
	})

	// readiness — пинг к БД с таймаутом.
	readyFn := func(ctx context.Context) error { return pool.Ping(ctx) }

	httpServer := httpsrv.New(cfg.HTTP.Addr,
		cfg.HTTP.ReadTimeout, cfg.HTTP.WriteTimeout, cfg.HTTP.IdleTimeout,
		httpsrv.Deps{
			Auth:     svc,
			Keystore: ks,
			Logger:   log.Named("http"),
			Metrics:  metrics,
			Ready:    readyFn,
		},
	)
	grpcServer := grpcsrv.New(cfg.GRPC.Addr, grpcsrv.Deps{
		Auth:     svc,
		Keystore: ks,
		Logger:   log.Named("grpc"),
		Metrics:  metrics,
	})
	metricsServer := newMetricsServer(cfg.Metrics.Addr, metrics, readyFn)

	rootCtx, cancel := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer cancel()

	// keystore rotation в фоне
	stopRotate := make(chan struct{})
	go func() {
		ks.Run(stopRotate)
	}()

	g, gctx := errgroup.WithContext(rootCtx)
	g.Go(func() error { return httpServer.Start() })
	g.Go(func() error { return grpcServer.Start() })
	g.Go(func() error { return metricsServer.Start() })

	// shutdown по сигналу или ошибке любого из серверов
	g.Go(func() error {
		<-gctx.Done()
		log.Info("shutdown signal received")
		shCtx, shCancel := context.WithTimeout(context.Background(), cfg.ShutdownTTL)
		defer shCancel()

		// запускаем shutdown параллельно — каждый со своим под-таймаутом,
		// но ограничены общим shCtx
		var firstErr error
		shErrs := make(chan error, 3)
		go func() { shErrs <- httpServer.Shutdown(shCtx) }()
		go func() { shErrs <- grpcServer.Shutdown(shCtx) }()
		go func() { shErrs <- metricsServer.Shutdown(shCtx) }()
		for i := 0; i < 3; i++ {
			if e := <-shErrs; e != nil && firstErr == nil {
				firstErr = e
			}
		}
		close(stopRotate)
		return firstErr
	})

	if err := g.Wait(); err != nil && !errors.Is(err, context.Canceled) {
		log.Error("run failed", zap.Error(err))
		return err
	}
	log.Info("auth-service stopped cleanly")
	return nil
}

// --- отдельный metrics-listener ---

type metricsServer struct {
	srv *http.Server
}

func newMetricsServer(addr string, m *observability.Metrics, ready func(context.Context) error) *metricsServer {
	mux := http.NewServeMux()
	mux.Handle("/metrics", m.Handler())
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		if err := ready(ctx); err != nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	return &metricsServer{srv: &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}}
}

func (s *metricsServer) Start() error {
	if err := s.srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}
func (s *metricsServer) Shutdown(ctx context.Context) error {
	return s.srv.Shutdown(ctx)
}
