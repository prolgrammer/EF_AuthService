//go:build proto

package grpcsrv

import (
	"context"
	"errors"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/eventflow/auth-service/internal/domain"
	authv1 "github.com/eventflow/auth-service/pkg/pb/auth/v1"
)

type authGRPCHandler struct {
	authv1.UnimplementedAuthServer
	deps Deps
}

func newAuthGRPCHandler(d Deps) *authGRPCHandler { return &authGRPCHandler{deps: d} }

func (h *authGRPCHandler) Login(ctx context.Context, req *authv1.LoginRequest) (*authv1.TokenPair, error) {
	pair, err := h.deps.Auth.Login(ctx, req.GetEmail(), req.GetPassword())
	if err != nil {
		return nil, mapErr(err)
	}
	return &authv1.TokenPair{
		AccessToken:       pair.AccessToken,
		RefreshToken:      pair.RefreshToken,
		AccessTtlSeconds:  int32(pair.AccessTTL.Seconds()),
		RefreshTtlSeconds: int32(pair.RefreshTTL.Seconds()),
	}, nil
}

func (h *authGRPCHandler) Refresh(ctx context.Context, req *authv1.RefreshRequest) (*authv1.TokenPair, error) {
	pair, err := h.deps.Auth.Refresh(ctx, req.GetRefreshToken())
	if err != nil {
		return nil, mapErr(err)
	}
	return &authv1.TokenPair{
		AccessToken:       pair.AccessToken,
		RefreshToken:      pair.RefreshToken,
		AccessTtlSeconds:  int32(pair.AccessTTL.Seconds()),
		RefreshTtlSeconds: int32(pair.RefreshTTL.Seconds()),
	}, nil
}

func (h *authGRPCHandler) ValidateToken(ctx context.Context, req *authv1.ValidateTokenRequest) (*authv1.ValidateTokenResponse, error) {
	c, err := h.deps.Auth.Validate(ctx, req.GetAccessToken())
	if err != nil {
		// для api-gateway это «not valid», а не ошибка вызова.
		return &authv1.ValidateTokenResponse{Valid: false}, nil
	}
	return &authv1.ValidateTokenResponse{
		Valid:     true,
		UserId:    c.UserID.String(),
		ExpiresAt: timestamppb.New(c.ExpiresAt),
		Scopes:    c.Scopes,
	}, nil
}

func (h *authGRPCHandler) JWKS(_ context.Context, _ *authv1.JWKSRequest) (*authv1.JWKSResponse, error) {
	jwks := h.deps.Keystore.JWKS()
	out := &authv1.JWKSResponse{Keys: make([]*authv1.JWK, 0, len(jwks.Keys))}
	for _, k := range jwks.Keys {
		out.Keys = append(out.Keys, &authv1.JWK{
			Kty: k.Kty, Use: k.Use, Alg: k.Alg, Kid: k.Kid, N: k.N, E: k.E,
		})
	}
	return out, nil
}

// mapErr — доменные ошибки → grpc status.
func mapErr(err error) error {
	switch {
	case errors.Is(err, domain.ErrEmailTaken):
		return status.Error(codes.AlreadyExists, "email_taken")
	case errors.Is(err, domain.ErrInvalidEmail), errors.Is(err, domain.ErrWeakPassword):
		return status.Error(codes.InvalidArgument, err.Error())
	case errors.Is(err, domain.ErrInvalidCredentials), errors.Is(err, domain.ErrUserNotFound):
		return status.Error(codes.Unauthenticated, "invalid_credentials")
	case errors.Is(err, domain.ErrTokenExpired):
		return status.Error(codes.Unauthenticated, "token_expired")
	case errors.Is(err, domain.ErrTokenRevoked):
		return status.Error(codes.Unauthenticated, "token_revoked")
	case errors.Is(err, domain.ErrTokenInvalid):
		return status.Error(codes.Unauthenticated, "token_invalid")
	default:
		return status.Error(codes.Internal, "internal")
	}
}
