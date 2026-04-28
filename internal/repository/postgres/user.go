package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/eventflow/auth-service/internal/domain"
)

const uniqueViolation = "23505"

// UserRepo — реализация domain.UserRepository поверх pgxpool.Pool.
type UserRepo struct {
	pool *pgxpool.Pool
}

// NewUserRepo конструктор.
func NewUserRepo(pool *pgxpool.Pool) *UserRepo {
	return &UserRepo{pool: pool}
}

// Create сохраняет пользователя. ErrEmailTaken при unique violation.
func (r *UserRepo) Create(ctx context.Context, u *domain.User) error {
	const q = `
		INSERT INTO users (id, email, password_hash, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5)
	`
	if u.ID == uuid.Nil {
		u.ID = uuid.New()
	}
	_, err := r.pool.Exec(ctx, q, u.ID, u.Email, u.PasswordHash, u.CreatedAt, u.UpdatedAt)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == uniqueViolation {
			return domain.ErrEmailTaken
		}
		return fmt.Errorf("insert user: %w", err)
	}
	return nil
}

// FindByEmail возвращает domain.ErrUserNotFound если не найден.
func (r *UserRepo) FindByEmail(ctx context.Context, email string) (*domain.User, error) {
	const q = `
		SELECT id, email, password_hash, created_at, updated_at
		FROM users WHERE email = $1
	`
	var u domain.User
	err := r.pool.QueryRow(ctx, q, email).Scan(
		&u.ID, &u.Email, &u.PasswordHash, &u.CreatedAt, &u.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, domain.ErrUserNotFound
		}
		return nil, fmt.Errorf("select user by email: %w", err)
	}
	return &u, nil
}

// FindByID — то же по primary key.
func (r *UserRepo) FindByID(ctx context.Context, id uuid.UUID) (*domain.User, error) {
	const q = `
		SELECT id, email, password_hash, created_at, updated_at
		FROM users WHERE id = $1
	`
	var u domain.User
	err := r.pool.QueryRow(ctx, q, id).Scan(
		&u.ID, &u.Email, &u.PasswordHash, &u.CreatedAt, &u.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, domain.ErrUserNotFound
		}
		return nil, fmt.Errorf("select user by id: %w", err)
	}
	return &u, nil
}
