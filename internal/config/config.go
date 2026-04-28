package config

import (
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/kelseyhightower/envconfig"
)

// Env — окружение выполнения.
type Env string

const (
	EnvDev     Env = "dev"
	EnvStaging Env = "staging"
	EnvProd    Env = "prod"
)

// Config — корневая структура конфигурации сервиса.
type Config struct {
	Env        Env    `envconfig:"ENV" default:"dev"`
	LogLevel   string `envconfig:"LOG_LEVEL" default:"info"`
	InstanceID string `envconfig:"INSTANCE_ID"`

	HTTP        HTTPConfig
	GRPC        GRPCConfig
	DB          DBConfig
	JWT         JWTConfig
	Metrics     MetricsConfig
	Tracing     TracingConfig
	ShutdownTTL time.Duration `envconfig:"SHUTDOWN_TIMEOUT" default:"30s"`
}

// HTTPConfig — параметры публичного REST-сервера.
// envconfig строит ключ как AUTH_HTTP_<TAG>, поэтому теги указываем без
// дублирующего префикса "HTTP_".
type HTTPConfig struct {
	Addr         string        `envconfig:"ADDR" default:":8080"`
	ReadTimeout  time.Duration `envconfig:"READ_TIMEOUT" default:"10s"`
	WriteTimeout time.Duration `envconfig:"WRITE_TIMEOUT" default:"15s"`
	IdleTimeout  time.Duration `envconfig:"IDLE_TIMEOUT" default:"60s"`
}

// GRPCConfig — параметры внутреннего gRPC-сервера.
type GRPCConfig struct {
	Addr string `envconfig:"ADDR" default:":9090"`
}

// DBConfig — параметры пула PostgreSQL.
// Итоговые переменные окружения: AUTH_DB_DSN, AUTH_DB_MAX_CONNS, …
type DBConfig struct {
	DSN            string `envconfig:"DSN" required:"true"`
	MaxConns       int32  `envconfig:"MAX_CONNS" default:"20"`
	MinConns       int32  `envconfig:"MIN_CONNS" default:"2"`
	MigrateOnStart bool   `envconfig:"MIGRATE_ON_START" default:"true"`
	MigrationsDir  string `envconfig:"MIGRATIONS_DIR" default:"./migrations"`
}

// JWTConfig — параметры выпуска и ротации JWT.
// Итоговые переменные окружения: AUTH_JWT_ISSUER, AUTH_JWT_ACCESS_TTL, …
type JWTConfig struct {
	Issuer       string        `envconfig:"ISSUER" default:"eventflow-auth"`
	AccessTTL    time.Duration `envconfig:"ACCESS_TTL" default:"15m"`
	RefreshTTL   time.Duration `envconfig:"REFRESH_TTL" default:"720h"`
	KeyDir       string        `envconfig:"KEY_DIR" default:"./keys"`
	RotateEvery  time.Duration `envconfig:"KEY_ROTATE_EVERY" default:"720h"`
	OverlapFor   time.Duration `envconfig:"KEY_OVERLAP" default:"72h"`
	JWKSCacheTTL time.Duration `envconfig:"JWKS_CACHE_TTL" default:"5m"`
}

// MetricsConfig — отдельный listener для Prometheus.
type MetricsConfig struct {
	Addr string `envconfig:"ADDR" default:":2112"`
}

// TracingConfig — OpenTelemetry / OTLP gRPC.
// Итоговые переменные окружения: AUTH_TRACING_ENABLED, AUTH_TRACING_OTLP_ENDPOINT, …
type TracingConfig struct {
	Enabled      bool    `envconfig:"ENABLED" default:"false"`
	OTLPEndpoint string  `envconfig:"OTLP_ENDPOINT" default:"otel-collector:4317"`
	SampleRatio  float64 `envconfig:"SAMPLE_RATIO" default:"0.01"`
}

// Load парсит ENV с префиксом AUTH_, валидирует и возвращает Config.
func Load() (*Config, error) {
	var cfg Config
	if err := envconfig.Process("AUTH", &cfg); err != nil {
		return nil, fmt.Errorf("envconfig: %w", err)
	}
	if cfg.InstanceID == "" {
		cfg.InstanceID = uuid.NewString()
	}
	if err := cfg.validate(); err != nil {
		return nil, fmt.Errorf("config validate: %w", err)
	}
	return &cfg, nil
}

func (c *Config) validate() error {
	switch c.Env {
	case EnvDev, EnvStaging, EnvProd:
	default:
		return fmt.Errorf("unknown env %q", c.Env)
	}
	if c.JWT.AccessTTL <= 0 || c.JWT.RefreshTTL <= 0 {
		return fmt.Errorf("jwt ttl must be positive")
	}
	if c.JWT.AccessTTL >= c.JWT.RefreshTTL {
		return fmt.Errorf("jwt access ttl must be < refresh ttl")
	}
	if c.JWT.OverlapFor >= c.JWT.RotateEvery {
		return fmt.Errorf("jwt overlap must be < rotate period")
	}
	if c.DB.MinConns > c.DB.MaxConns {
		return fmt.Errorf("db min conns > max conns")
	}
	return nil
}
