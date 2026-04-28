package domain

import (
	"context"
	"net/mail"
	"strings"
	"time"

	"github.com/google/uuid"
)

// User — внутренний пользователь платформы (аналитик/менеджер).
//
// Хеш пароля никогда не покидает сервис — для DTO в транспортном слое
// заводятся отдельные структуры без этого поля.
type User struct {
	ID           uuid.UUID
	Email        string
	PasswordHash []byte
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

// NormalizeEmail приводит email к каноничной форме (lower-case, trim).
// CITEXT в PostgreSQL даст case-insensitive uniqueness, но мы дополнительно
// нормализуем здесь для гарантии стабильного хеша при логах/трейсах.
func NormalizeEmail(s string) string {
	return strings.ToLower(strings.TrimSpace(s))
}

// ValidateEmail — RFC 5322-совместимая поверхностная проверка.
func ValidateEmail(s string) error {
	if _, err := mail.ParseAddress(s); err != nil {
		return ErrInvalidEmail
	}
	return nil
}

// MinPasswordLen — минимальная длина пароля. Без верхнего лимита — bcrypt
// сам обрежет до 72 байт; настраивать сюда сложные правила (заглавные/
// спецсимволы) намеренно не стали — соответствует современным NIST
// рекомендациям (длина важнее composition).
const MinPasswordLen = 10

// ValidatePassword — длина и базовая проверка на «не пустой».
func ValidatePassword(p string) error {
	if len(p) < MinPasswordLen {
		return ErrWeakPassword
	}
	return nil
}

// UserRepository — порт для слоя хранения пользователей.
type UserRepository interface {
	Create(ctx context.Context, u *User) error
	FindByEmail(ctx context.Context, email string) (*User, error)
	FindByID(ctx context.Context, id uuid.UUID) (*User, error)
}
