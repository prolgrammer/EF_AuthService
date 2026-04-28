//go:build proto

package grpcsrv

import (
	authv1 "github.com/eventflow/auth-service/pkg/pb/auth/v1"
)

// registerAuth — реальная регистрация AuthService поверх сгенерированного proto.
func registerAuth(s *Server) {
	authv1.RegisterAuthServer(s.srv, newAuthGRPCHandler(s.deps))
}
