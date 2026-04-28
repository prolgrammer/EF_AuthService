package auth

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"github.com/eventflow/auth-service/internal/domain"
)

// keystorePort — то, что нужно JWT issuer-у от keystore. Объявление здесь
// (а не импорт интерфейса из keystore) даёт обратную направленность зависимостей.
type keystorePort interface {
	SigningKey() (kid string, priv *rsa.PrivateKey)
	PublicKey(kid string) (*rsa.PublicKey, error)
}

// JWTIssuer выпускает access-токены и валидирует их.
//
// Refresh-токены — opaque-строки (не JWT), их жизненный цикл управляется
// в БД (см. domain.RefreshToken).
type JWTIssuer struct {
	ks         keystorePort
	issuer     string
	accessTTL  time.Duration
	refreshTTL time.Duration
}

// NewJWTIssuer конструктор.
func NewJWTIssuer(ks keystorePort, issuer string, accessTTL, refreshTTL time.Duration) *JWTIssuer {
	return &JWTIssuer{ks: ks, issuer: issuer, accessTTL: accessTTL, refreshTTL: refreshTTL}
}

// IssueAccessToken — подписывает RS256 JWT.
func (j *JWTIssuer) IssueAccessToken(userID uuid.UUID, scopes []string, now time.Time) (string, time.Time, string, error) {
	kid, priv := j.ks.SigningKey()
	jti := uuid.NewString()
	exp := now.Add(j.accessTTL)
	claims := jwt.MapClaims{
		"iss":    j.issuer,
		"sub":    userID.String(),
		"iat":    now.Unix(),
		"exp":    exp.Unix(),
		"jti":    jti,
		"scopes": scopes,
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = kid
	signed, err := tok.SignedString(priv)
	if err != nil {
		return "", time.Time{}, "", fmt.Errorf("sign jwt: %w", err)
	}
	return signed, exp, jti, nil
}

// ParseAccessToken проверяет подпись и срок действия. Возвращает Claims.
//
// Принципы:
//   - алгоритм фиксирован (RS256) — никаких none/HS256 атак;
//   - kid обязателен — ключ берём только из keystore;
//   - exp/iat/iss проверяются библиотечной валидацией.
func (j *JWTIssuer) ParseAccessToken(token string) (*domain.Claims, error) {
	parser := jwt.NewParser(
		jwt.WithValidMethods([]string{"RS256"}),
		jwt.WithIssuer(j.issuer),
		jwt.WithExpirationRequired(),
	)
	parsed, err := parser.Parse(token, func(t *jwt.Token) (any, error) {
		kid, _ := t.Header["kid"].(string)
		if kid == "" {
			return nil, errors.New("missing kid")
		}
		return j.ks.PublicKey(kid)
	})
	if err != nil {
		switch {
		case errors.Is(err, jwt.ErrTokenExpired):
			return nil, domain.ErrTokenExpired
		case errors.Is(err, jwt.ErrTokenSignatureInvalid),
			errors.Is(err, jwt.ErrTokenMalformed),
			errors.Is(err, jwt.ErrTokenUnverifiable):
			return nil, domain.ErrTokenInvalid
		default:
			return nil, fmt.Errorf("%w: %v", domain.ErrTokenInvalid, err)
		}
	}
	claims, ok := parsed.Claims.(jwt.MapClaims)
	if !ok {
		return nil, domain.ErrTokenInvalid
	}
	sub, _ := claims["sub"].(string)
	uid, err := uuid.Parse(sub)
	if err != nil {
		return nil, domain.ErrTokenInvalid
	}
	jti, _ := claims["jti"].(string)
	expF, _ := claims["exp"].(float64)
	iatF, _ := claims["iat"].(float64)

	scopes := []string{}
	if raw, ok := claims["scopes"].([]any); ok {
		for _, v := range raw {
			if s, ok := v.(string); ok {
				scopes = append(scopes, s)
			}
		}
	}
	return &domain.Claims{
		UserID:    uid,
		Issuer:    j.issuer,
		Subject:   sub,
		ExpiresAt: time.Unix(int64(expF), 0).UTC(),
		IssuedAt:  time.Unix(int64(iatF), 0).UTC(),
		JTI:       jti,
		Scopes:    scopes,
	}, nil
}

// NewRefreshToken генерирует opaque refresh-token. Возвращает (raw, hash).
func NewRefreshToken() (raw string, hash []byte, err error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", nil, fmt.Errorf("rand: %w", err)
	}
	raw = base64.RawURLEncoding.EncodeToString(buf)
	h := sha256.Sum256([]byte(raw))
	return raw, h[:], nil
}

// HashRefreshToken — хеш для поиска в БД.
func HashRefreshToken(raw string) []byte {
	h := sha256.Sum256([]byte(raw))
	return h[:]
}
