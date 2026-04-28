package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/eventflow/auth-service/internal/domain"
)

// RefreshTokenRepo реализует domain.RefreshTokenRepository.
type RefreshTokenRepo struct {
	pool *pgxpool.Pool
}

// NewRefreshTokenRepo конструктор.
func NewRefreshTokenRepo(pool *pgxpool.Pool) *RefreshTokenRepo {
	return &RefreshTokenRepo{pool: pool}
}

// Create сохраняет новый refresh.
func (r *RefreshTokenRepo) Create(ctx context.Context, rt *domain.RefreshToken) error {
	const q = `
		INSERT INTO refresh_tokens (id, user_id, token_hash, issued_at, expires_at)
		VALUES ($1, $2, $3, $4, $5)
	`
	if rt.ID == uuid.Nil {
		rt.ID = uuid.New()
	}
	_, err := r.pool.Exec(ctx, q,
		rt.ID, rt.UserID, rt.TokenHash, rt.IssuedAt, rt.ExpiresAt,
	)
	if err != nil {
		return fmt.Errorf("insert refresh: %w", err)
	}
	return nil
}

// FindByHash используется на /refresh: ищем по SHA-256(token).
func (r *RefreshTokenRepo) FindByHash(ctx context.Context, hash []byte) (*domain.RefreshToken, error) {
	const q = `
		SELECT id, user_id, token_hash, issued_at, expires_at, revoked_at, replaced_by
		FROM refresh_tokens WHERE token_hash = $1
	`
	var rt domain.RefreshToken
	err := r.pool.QueryRow(ctx, q, hash).Scan(
		&rt.ID, &rt.UserID, &rt.TokenHash, &rt.IssuedAt, &rt.ExpiresAt,
		&rt.RevokedAt, &rt.ReplacedBy,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, domain.ErrTokenInvalid
		}
		return nil, fmt.Errorf("select refresh: %w", err)
	}
	return &rt, nil
}

// MarkRotated помечает старый токен как заменённый — атомарно через UPDATE.
// Если токен уже был отозван — возвращает ErrTokenRevoked (это reuse-detection).
func (r *RefreshTokenRepo) MarkRotated(ctx context.Context, id, replacedBy uuid.UUID, at time.Time) error {
	const q = `
		UPDATE refresh_tokens
		SET revoked_at = $3, replaced_by = $2
		WHERE id = $1 AND revoked_at IS NULL
	`
	tag, err := r.pool.Exec(ctx, q, id, replacedBy, at)
	if err != nil {
		return fmt.Errorf("update refresh rotated: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return domain.ErrTokenRevoked
	}
	return nil
}

// RevokeAllForUser — массовая ревокация (например, при reuse-detection или
// смене пароля).
func (r *RefreshTokenRepo) RevokeAllForUser(ctx context.Context, userID uuid.UUID, at time.Time) error {
	const q = `
		UPDATE refresh_tokens
		SET revoked_at = $2
		WHERE user_id = $1 AND revoked_at IS NULL
	`
	if _, err := r.pool.Exec(ctx, q, userID, at); err != nil {
		return fmt.Errorf("revoke all refresh: %w", err)
	}
	return nil
}

// DeleteExpired — задача GC. Возвращает кол-во удалённых строк.
func (r *RefreshTokenRepo) DeleteExpired(ctx context.Context, before time.Time) (int64, error) {
	const q = `DELETE FROM refresh_tokens WHERE expires_at < $1`
	tag, err := r.pool.Exec(ctx, q, before)
	if err != nil {
		return 0, fmt.Errorf("delete expired: %w", err)
	}
	return tag.RowsAffected(), nil
}
