package domain

import "errors"

// Группы доменных ошибок. На транспортном уровне они мапятся на HTTP/gRPC коды,
// бизнес-логика никогда не возвращает «голые» строки.
var (
	ErrEmailTaken         = errors.New("email already in use")
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrUserNotFound       = errors.New("user not found")
	ErrTokenInvalid       = errors.New("token invalid")
	ErrTokenExpired       = errors.New("token expired")
	ErrTokenRevoked       = errors.New("token revoked")
	ErrInvalidEmail       = errors.New("invalid email")
	ErrWeakPassword       = errors.New("password too weak")
)
