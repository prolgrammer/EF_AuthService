package httpsrv

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	chimw "github.com/go-chi/chi/v5/middleware"
	"go.uber.org/zap"

	"github.com/eventflow/auth-service/internal/keystore"
	"github.com/eventflow/auth-service/internal/observability"
	authsvc "github.com/eventflow/auth-service/internal/service/auth"
)

// Deps — внешние зависимости сервера.
type Deps struct {
	Auth     *authsvc.Service
	Keystore *keystore.Store
	Logger   *zap.Logger
	Metrics  *observability.Metrics
	// Ready — функция-проверка готовности (DB ping и пр.).
	Ready func(ctx context.Context) error
}

// Server — обёртка над *http.Server.
type Server struct {
	srv    *http.Server
	logger *zap.Logger
}

// New собирает сервер с роутингом.
func New(addr string, readT, writeT, idleT time.Duration, deps Deps) *Server {
	r := chi.NewRouter()

	r.Use(chimw.RequestID)
	r.Use(chimw.RealIP)
	r.Use(chimw.Recoverer)
	r.Use(loggingMiddleware(deps.Logger))
	r.Use(metricsMiddleware(deps.Metrics))

	// system endpoints — отдельный listener под ./metrics остаётся,
	// но и здесь дублируем /healthz/readyz для удобства проб.
	r.Get("/healthz", healthHandler)
	r.Get("/readyz", readyHandler(deps.Ready))

	// JWKS публичный — вызывается api-gateway без авторизации.
	r.Get("/jwks.json", jwksHandler(deps.Keystore))
	r.Get("/.well-known/jwks.json", jwksHandler(deps.Keystore))

	r.Route("/v1/auth", func(r chi.Router) {
		ah := newAuthHandler(deps.Auth, deps.Logger)
		r.Post("/register", ah.register)
		r.Post("/login", ah.login)
		r.Post("/refresh", ah.refresh)
		r.Post("/validate", ah.validate)
	})

	srv := &http.Server{
		Addr:              addr,
		Handler:           r,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       readT,
		WriteTimeout:      writeT,
		IdleTimeout:       idleT,
	}
	return &Server{srv: srv, logger: deps.Logger}
}

// Start запускает listener; блокирующий вызов.
func (s *Server) Start() error {
	s.logger.Info("http server starting", zap.String("addr", s.srv.Addr))
	if err := s.srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// Shutdown — корректное завершение.
func (s *Server) Shutdown(ctx context.Context) error {
	s.logger.Info("http server shutting down")
	return s.srv.Shutdown(ctx)
}
