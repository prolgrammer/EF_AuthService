package logger

import (
	"fmt"
	"strings"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// New возвращает Logger; в dev — человекочитаемый, в prod — JSON.
//
// Поля service и instance проставляются всем сообщениям, что упрощает
// маршрутизацию в Logstash/ELK.
func New(env, level, service, instance string) (*zap.Logger, error) {
	lvl, err := parseLevel(level)
	if err != nil {
		return nil, err
	}

	var cfg zap.Config
	if strings.EqualFold(env, "dev") {
		cfg = zap.NewDevelopmentConfig()
	} else {
		cfg = zap.NewProductionConfig()
	}
	cfg.Level = zap.NewAtomicLevelAt(lvl)
	cfg.EncoderConfig.TimeKey = "ts"
	cfg.EncoderConfig.MessageKey = "msg"
	cfg.EncoderConfig.LevelKey = "level"
	cfg.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
	cfg.DisableStacktrace = strings.EqualFold(env, "dev")

	log, err := cfg.Build(zap.AddCallerSkip(0))
	if err != nil {
		return nil, fmt.Errorf("zap build: %w", err)
	}
	return log.With(
		zap.String("service", service),
		zap.String("instance", instance),
	), nil
}

func parseLevel(s string) (zapcore.Level, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "debug":
		return zapcore.DebugLevel, nil
	case "", "info":
		return zapcore.InfoLevel, nil
	case "warn", "warning":
		return zapcore.WarnLevel, nil
	case "error":
		return zapcore.ErrorLevel, nil
	default:
		return zapcore.InfoLevel, fmt.Errorf("unknown log level %q", s)
	}
}
