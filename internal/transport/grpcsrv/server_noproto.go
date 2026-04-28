//go:build !proto

package grpcsrv

// registerAuth — реальная регистрация AuthService без proto.
func registerAuth(s *Server) {
	s.logger.Warn("AuthService is NOT registered: build with -tags proto after `make proto`")
}
