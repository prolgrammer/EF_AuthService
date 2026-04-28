package observability

import (
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Metrics — все метрики сервиса. Передаётся явно по слоям.
type Metrics struct {
	registry *prometheus.Registry

	HTTPReqTotal    *prometheus.CounterVec
	HTTPReqDuration *prometheus.HistogramVec

	GRPCReqTotal    *prometheus.CounterVec
	GRPCReqDuration *prometheus.HistogramVec

	LoginAttempts   *prometheus.CounterVec
	TokensIssued    *prometheus.CounterVec
	TokensValidated *prometheus.CounterVec
	KeyRotations    prometheus.Counter
	ActiveJWKKeys   prometheus.Gauge
}

// NewMetrics регистрирует метрики в собственном Registry (не в DefaultRegisterer)
// — так разные тестовые инстансы не конфликтуют.
func NewMetrics() *Metrics {
	reg := prometheus.NewRegistry()
	reg.MustRegister(
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
	)

	m := &Metrics{
		registry: reg,
		HTTPReqTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "http_requests_total",
			Help: "Total HTTP requests by route/method/status.",
		}, []string{"method", "route", "status"}),
		HTTPReqDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "http_request_duration_seconds",
			Help:    "HTTP request duration in seconds.",
			Buckets: []float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5},
		}, []string{"method", "route"}),
		GRPCReqTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "grpc_server_handled_total",
			Help: "Total gRPC requests handled.",
		}, []string{"method", "code"}),
		GRPCReqDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "grpc_server_handling_seconds",
			Help:    "gRPC server handling duration.",
			Buckets: []float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1},
		}, []string{"method"}),
		LoginAttempts: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "auth_login_attempts_total",
			Help: "Login attempts by result (success|invalid_credentials|error).",
		}, []string{"result"}),
		TokensIssued: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "auth_tokens_issued_total",
			Help: "Issued tokens by kind (access|refresh).",
		}, []string{"kind"}),
		TokensValidated: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "auth_tokens_validated_total",
			Help: "Token validation results.",
		}, []string{"result"}),
		KeyRotations: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "auth_key_rotations_total",
			Help: "Number of signing-key rotations performed.",
		}),
		ActiveJWKKeys: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "auth_jwks_active_keys",
			Help: "Number of public keys currently exposed via JWKS.",
		}),
	}
	reg.MustRegister(
		m.HTTPReqTotal, m.HTTPReqDuration,
		m.GRPCReqTotal, m.GRPCReqDuration,
		m.LoginAttempts, m.TokensIssued, m.TokensValidated,
		m.KeyRotations, m.ActiveJWKKeys,
	)
	return m
}

// Handler — http-handler для endpoint /metrics.
func (m *Metrics) Handler() http.Handler {
	return promhttp.HandlerFor(m.registry, promhttp.HandlerOpts{Registry: m.registry})
}

// ObserveHTTP — удобный helper для middleware.
func (m *Metrics) ObserveHTTP(method, route string, status int, dur time.Duration) {
	m.HTTPReqTotal.WithLabelValues(method, route, httpStatusBucket(status)).Inc()
	m.HTTPReqDuration.WithLabelValues(method, route).Observe(dur.Seconds())
}

// ObserveGRPC — helper для gRPC-интерсептора.
func (m *Metrics) ObserveGRPC(method, code string, dur time.Duration) {
	m.GRPCReqTotal.WithLabelValues(method, code).Inc()
	m.GRPCReqDuration.WithLabelValues(method).Observe(dur.Seconds())
}

// httpStatusBucket округляет статус до бакета (для cardinality).
func httpStatusBucket(s int) string {
	switch {
	case s >= 200 && s < 300:
		return "2xx"
	case s >= 300 && s < 400:
		return "3xx"
	case s >= 400 && s < 500:
		return "4xx"
	case s >= 500:
		return "5xx"
	default:
		return "1xx"
	}
}

// IncLogin удовлетворяет authsvc.MetricsHook.
func (m *Metrics) IncLogin(result string) { m.LoginAttempts.WithLabelValues(result).Inc() }

// IncTokensIssued удовлетворяет authsvc.MetricsHook.
func (m *Metrics) IncTokensIssued(kind string) { m.TokensIssued.WithLabelValues(kind).Inc() }

// IncTokensValidated удовлетворяет authsvc.MetricsHook.
func (m *Metrics) IncTokensValidated(result string) { m.TokensValidated.WithLabelValues(result).Inc() }
