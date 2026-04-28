package domain

import (
	"context"
	"time"

	"github.com/google/uuid"
)

// TokenPair — выпущенная пара access+refresh.
type TokenPair struct {
	AccessToken  string
	RefreshToken string
	AccessTTL    time.Duration
	RefreshTTL   time.Duration
}

// Claims — содержимое access-токена. Сюда попадает только то, что нужно
// downstream-сервисам для авторизации (никаких email/имени).
type Claims struct {
	UserID    uuid.UUID
	Issuer    string
	Subject   string
	ExpiresAt time.Time
	IssuedAt  time.Time
	JTI       string // jwt id — для аудита
	Scopes    []string
}

// RefreshToken — серверная запись про refresh-токен. Храним hash, не сам токен.
//
// Подход: сам refresh-токен — opaque-строка (не JWT) длиной 32 байта в base64url,
// хранится только её SHA-256 хеш — компрометация БД не раскрывает токены.
// Rotation: при каждом /refresh старая запись помечается revoked, выпускается новая.
// Это даёт refresh-token reuse detection (см. RFC 6819 §5.2.2.3).
type RefreshToken struct {
	ID        uuid.UUID
	UserID    uuid.UUID
	TokenHash []byte
	IssuedAt  time.Time
	ExpiresAt time.Time
	RevokedAt *time.Time
	// ReplacedBy указывает, что этот токен был ротирован — если приходит
	// рефреш по уже ротированному токену, это сильный сигнал компрометации:
	// нужно отозвать всю цепочку.
	ReplacedBy *uuid.UUID
}

// IsActive — токен не истёк и не отозван.
func (rt *RefreshToken) IsActive(now time.Time) bool {
	if rt.RevokedAt != nil {
		return false
	}
	return now.Before(rt.ExpiresAt)
}

// RefreshTokenRepository — порт для refresh-токенов.
type RefreshTokenRepository interface {
	Create(ctx context.Context, rt *RefreshToken) error
	FindByHash(ctx context.Context, hash []byte) (*RefreshToken, error)
	MarkRotated(ctx context.Context, id, replacedBy uuid.UUID, at time.Time) error
	RevokeAllForUser(ctx context.Context, userID uuid.UUID, at time.Time) error
	DeleteExpired(ctx context.Context, before time.Time) (int64, error)
}
