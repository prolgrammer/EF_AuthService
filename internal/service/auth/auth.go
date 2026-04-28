package auth

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"

	"github.com/eventflow/auth-service/internal/domain"
)

// Clock — абстракция времени (упрощает тесты).
type Clock interface{ Now() time.Time }

type realClock struct{}

func (realClock) Now() time.Time { return time.Now().UTC() }

// MetricsHook — узкий интерфейс «всё, что сервис обновляет в Prometheus».
// Реальная *observability.Metrics его удовлетворяет — но пакет не зависит
// от observability напрямую (DI через интерфейс).
type MetricsHook interface {
	IncLogin(result string)
	IncTokensIssued(kind string)
	IncTokensValidated(result string)
}

type nopMetrics struct{}

func (nopMetrics) IncLogin(string)           {}
func (nopMetrics) IncTokensIssued(string)    {}
func (nopMetrics) IncTokensValidated(string) {}

// Service — основной use-case.
type Service struct {
	users    domain.UserRepository
	tokens   domain.RefreshTokenRepository
	jwt      *JWTIssuer
	logger   *zap.Logger
	clock    Clock
	bcryptCo int
	metrics  MetricsHook
}

// Options — конструктор.
type Options struct {
	Users      domain.UserRepository
	Tokens     domain.RefreshTokenRepository
	JWT        *JWTIssuer
	Logger     *zap.Logger
	Clock      Clock
	BcryptCost int
	Metrics    MetricsHook
}

// New собирает Service.
func New(o Options) *Service {
	if o.Clock == nil {
		o.Clock = realClock{}
	}
	if o.Logger == nil {
		o.Logger = zap.NewNop()
	}
	if o.BcryptCost == 0 {
		o.BcryptCost = bcrypt.DefaultCost
	}
	if o.Metrics == nil {
		o.Metrics = nopMetrics{}
	}
	return &Service{
		users:    o.Users,
		tokens:   o.Tokens,
		jwt:      o.JWT,
		logger:   o.Logger,
		clock:    o.Clock,
		bcryptCo: o.BcryptCost,
		metrics:  o.Metrics,
	}
}

// Register создаёт нового пользователя.
func (s *Service) Register(ctx context.Context, email, password string) (uuid.UUID, error) {
	email = domain.NormalizeEmail(email)
	if err := domain.ValidateEmail(email); err != nil {
		return uuid.Nil, err
	}
	if err := domain.ValidatePassword(password); err != nil {
		return uuid.Nil, err
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), s.bcryptCo)
	if err != nil {
		return uuid.Nil, fmt.Errorf("bcrypt: %w", err)
	}
	now := s.clock.Now()
	u := &domain.User{
		ID:           uuid.New(),
		Email:        email,
		PasswordHash: hash,
		CreatedAt:    now,
		UpdatedAt:    now,
	}
	if err := s.users.Create(ctx, u); err != nil {
		return uuid.Nil, err
	}
	s.logger.Info("user registered", zap.String("user_id", u.ID.String()))
	return u.ID, nil
}

// Login сверяет пароль и выпускает пару токенов.
func (s *Service) Login(ctx context.Context, email, password string) (*domain.TokenPair, error) {
	email = domain.NormalizeEmail(email)
	u, err := s.users.FindByEmail(ctx, email)
	if err != nil {
		// единый ответ для несуществующего user и неверного пароля,
		// чтобы не давать перебором различать наличие email в системе.
		if errors.Is(err, domain.ErrUserNotFound) {
			s.metrics.IncLogin("invalid_credentials")
			// дополнительно сжигаем время bcrypt, чтобы убрать timing-side-channel.
			_ = bcrypt.CompareHashAndPassword(getDummyHash(), []byte(password))
			return nil, domain.ErrInvalidCredentials
		}
		s.metrics.IncLogin("error")
		return nil, err
	}
	if err := bcrypt.CompareHashAndPassword(u.PasswordHash, []byte(password)); err != nil {
		s.metrics.IncLogin("invalid_credentials")
		return nil, domain.ErrInvalidCredentials
	}
	pair, _, err := s.issuePair(ctx, u.ID)
	if err != nil {
		s.metrics.IncLogin("error")
		return nil, err
	}
	s.metrics.IncLogin("success")
	return pair, nil
}

// Refresh — ротация: проверяет refresh-токен, ревокает старый, выпускает новый.
//
// Если приходит уже отозванный токен — это либо retry, либо reuse-attack.
// В обоих случаях надёжная стратегия — отозвать ВСЕ refresh-токены пользователя
// и заставить логиниться заново.
func (s *Service) Refresh(ctx context.Context, refreshRaw string) (*domain.TokenPair, error) {
	hash := HashRefreshToken(refreshRaw)
	rt, err := s.tokens.FindByHash(ctx, hash)
	if err != nil {
		return nil, err
	}
	now := s.clock.Now()
	if !rt.IsActive(now) {
		// reuse-detection — каскадно ревокаем
		_ = s.tokens.RevokeAllForUser(ctx, rt.UserID, now)
		s.logger.Warn("refresh-token reuse detected, revoking user tokens",
			zap.String("user_id", rt.UserID.String()),
			zap.String("token_id", rt.ID.String()),
		)
		return nil, domain.ErrTokenRevoked
	}
	pair, newID, err := s.issuePair(ctx, rt.UserID)
	if err != nil {
		return nil, err
	}
	// связываем старый -> новый (rotation chain для reuse-detection)
	if err := s.tokens.MarkRotated(ctx, rt.ID, newID, now); err != nil {
		return nil, err
	}
	return pair, nil
}

// Validate — проверяет access-токен и возвращает его claims.
func (s *Service) Validate(_ context.Context, accessToken string) (*domain.Claims, error) {
	c, err := s.jwt.ParseAccessToken(accessToken)
	if err != nil {
		switch {
		case errors.Is(err, domain.ErrTokenExpired):
			s.metrics.IncTokensValidated("expired")
		default:
			s.metrics.IncTokensValidated("invalid")
		}
		return nil, err
	}
	s.metrics.IncTokensValidated("valid")
	return c, nil
}

// issuePair — общий код для Login и Refresh.
//
// Возвращает пару токенов и ID только что созданной refresh-записи —
// это нужно Refresh-методу, чтобы выставить replaced_by = newID и таким
// образом построить rotation chain для reuse-detection.
func (s *Service) issuePair(ctx context.Context, userID uuid.UUID) (*domain.TokenPair, uuid.UUID, error) {
	now := s.clock.Now()
	access, _, _, err := s.jwt.IssueAccessToken(userID, defaultScopes, now)
	if err != nil {
		return nil, uuid.Nil, err
	}
	rawRefresh, hash, err := NewRefreshToken()
	if err != nil {
		return nil, uuid.Nil, err
	}
	rtID := uuid.New()
	rt := &domain.RefreshToken{
		ID:        rtID,
		UserID:    userID,
		TokenHash: hash,
		IssuedAt:  now,
		ExpiresAt: now.Add(s.jwt.refreshTTL),
	}
	if err := s.tokens.Create(ctx, rt); err != nil {
		return nil, uuid.Nil, err
	}
	s.metrics.IncTokensIssued("access")
	s.metrics.IncTokensIssued("refresh")
	return &domain.TokenPair{
		AccessToken:  access,
		RefreshToken: rawRefresh,
		AccessTTL:    s.jwt.accessTTL,
		RefreshTTL:   s.jwt.refreshTTL,
	}, rtID, nil
}

// dummyBcryptHash возвращает валидный bcrypt-хеш (рандомный, единожды
// сгенерированный) для timing-equalisation в Login: даже если пользователя
// нет, мы всё равно делаем CompareHashAndPassword чтобы атакующий не мог
// по latency определить наличие email в системе.
var (
	dummyBcryptHashOnce sync.Once
	dummyBcryptHash     []byte
)

func getDummyHash() []byte {
	dummyBcryptHashOnce.Do(func() {
		buf := make([]byte, 16)
		_, _ = rand.Read(buf)
		// cost совпадает с DefaultCost, чтобы compare-time соответствовал реальному
		hash, _ := bcrypt.GenerateFromPassword(buf, bcrypt.DefaultCost)
		dummyBcryptHash = hash
	})
	return dummyBcryptHash
}

// defaultScopes — минимум, который ставится при Login. На внешнем API можно
// будет добавить выбор скоупов, сейчас этого достаточно.
var defaultScopes = []string{"user"}
