package grpcsrv

import (
	"context"
	"time"

	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/status"

	"github.com/eventflow/auth-service/internal/observability"
)

// unaryMetricsInterceptor — RED для gRPC + одиночный structured-log.
func unaryMetricsInterceptor(m *observability.Metrics, log *zap.Logger) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		start := time.Now()
		resp, err := handler(ctx, req)
		code := status.Code(err).String()
		m.ObserveGRPC(info.FullMethod, code, time.Since(start))
		log.Debug("grpc call",
			zap.String("method", info.FullMethod),
			zap.String("code", code),
			zap.Duration("duration", time.Since(start)),
		)
		return resp, err
	}
}
