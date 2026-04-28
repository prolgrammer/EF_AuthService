package observability

import (
	"context"
	"fmt"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	tracesdk "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.24.0"
)

// TracingConfig — параметры инициализации OTel.
type TracingConfig struct {
	Enabled      bool
	Endpoint     string
	ServiceName  string
	Instance     string
	SampleRatio  float64
	Env          string
}

// Shutdown — функция корректного завершения провайдера. Безопасна к вызову
// при Enabled=false (вернёт nil).
type Shutdown func(context.Context) error

// InitTracing настраивает глобальный TracerProvider и propagation.
// Если Enabled=false — возвращает no-op shutdown.
func InitTracing(ctx context.Context, cfg TracingConfig) (Shutdown, error) {
	if !cfg.Enabled {
		return func(context.Context) error { return nil }, nil
	}

	exp, err := otlptrace.New(ctx, otlptracegrpc.NewClient(
		otlptracegrpc.WithEndpoint(cfg.Endpoint),
		otlptracegrpc.WithInsecure(),
		otlptracegrpc.WithTimeout(5*time.Second),
	))
	if err != nil {
		return nil, fmt.Errorf("otlp exporter: %w", err)
	}

	res, err := resource.New(ctx,
		resource.WithAttributes(
			semconv.ServiceName(cfg.ServiceName),
			semconv.ServiceInstanceID(cfg.Instance),
			semconv.DeploymentEnvironment(cfg.Env),
		),
	)
	if err != nil {
		return nil, fmt.Errorf("otel resource: %w", err)
	}

	tp := tracesdk.NewTracerProvider(
		tracesdk.WithBatcher(exp),
		tracesdk.WithResource(res),
		tracesdk.WithSampler(tracesdk.ParentBased(
			tracesdk.TraceIDRatioBased(cfg.SampleRatio),
		)),
	)
	otel.SetTracerProvider(tp)
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))

	return tp.Shutdown, nil
}
