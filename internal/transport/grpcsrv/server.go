package grpcsrv

import (
	"context"
	"errors"
	"net"

	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"

	"github.com/eventflow/auth-service/internal/keystore"
	"github.com/eventflow/auth-service/internal/observability"
	authsvc "github.com/eventflow/auth-service/internal/service/auth"
)

// Deps — внешние зависимости gRPC-сервера.
type Deps struct {
	Auth     *authsvc.Service
	Keystore *keystore.Store
	Logger   *zap.Logger
	Metrics  *observability.Metrics
}

// Server — обёртка над *grpc.Server.
type Server struct {
	srv      *grpc.Server
	addr     string
	logger   *zap.Logger
	healthSv *health.Server
	deps     Deps
}

// New собирает gRPC-сервер. Регистрация AuthServer выполняется в registerAuth,
// которая определена только при build-tag `proto` (см. server_proto.go).
func New(addr string, deps Deps) *Server {
	srv := grpc.NewServer(
		grpc.UnaryInterceptor(unaryMetricsInterceptor(deps.Metrics, deps.Logger)),
	)
	hs := health.NewServer()
	healthpb.RegisterHealthServer(srv, hs)
	hs.SetServingStatus("", healthpb.HealthCheckResponse_SERVING)

	s := &Server{srv: srv, addr: addr, logger: deps.Logger, healthSv: hs, deps: deps}
	registerAuth(s) // see server_proto.go (no-op when proto build-tag отсутствует)
	return s
}

// Start блокирующий.
func (s *Server) Start() error {
	lis, err := net.Listen("tcp", s.addr)
	if err != nil {
		return err
	}
	s.logger.Info("grpc server starting", zap.String("addr", s.addr))
	if err := s.srv.Serve(lis); err != nil && !errors.Is(err, grpc.ErrServerStopped) {
		return err
	}
	return nil
}

// Shutdown — GracefulStop.
func (s *Server) Shutdown(_ context.Context) error {
	s.logger.Info("grpc server shutting down")
	s.healthSv.SetServingStatus("", healthpb.HealthCheckResponse_NOT_SERVING)
	s.srv.GracefulStop()
	return nil
}
