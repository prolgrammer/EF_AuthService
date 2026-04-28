package httpsrv

import (
	"encoding/json"
	"errors"
	"net/http"

	"go.uber.org/zap"

	"github.com/eventflow/auth-service/internal/domain"
	authsvc "github.com/eventflow/auth-service/internal/service/auth"
)

type authHandler struct {
	svc    *authsvc.Service
	logger *zap.Logger
}

func newAuthHandler(svc *authsvc.Service, l *zap.Logger) *authHandler {
	return &authHandler{svc: svc, logger: l}
}

// --- DTO ---

type registerReq struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}
type registerResp struct {
	UserID string `json:"user_id"`
}

type loginReq struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}
type tokenPairResp struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token,omitempty"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"` // seconds
}

type refreshReq struct {
	RefreshToken string `json:"refresh_token"`
}

type validateReq struct {
	Token string `json:"token"`
}
type validateResp struct {
	Valid     bool     `json:"valid"`
	UserID    string   `json:"user_id,omitempty"`
	ExpiresAt int64    `json:"expires_at,omitempty"`
	Scopes    []string `json:"scopes,omitempty"`
}

// --- handlers ---

func (h *authHandler) register(w http.ResponseWriter, r *http.Request) {
	var req registerReq
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_body", err.Error())
		return
	}
	id, err := h.svc.Register(r.Context(), req.Email, req.Password)
	if err != nil {
		writeDomainError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, registerResp{UserID: id.String()})
}

func (h *authHandler) login(w http.ResponseWriter, r *http.Request) {
	var req loginReq
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_body", err.Error())
		return
	}
	pair, err := h.svc.Login(r.Context(), req.Email, req.Password)
	if err != nil {
		writeDomainError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, tokenPairResp{
		AccessToken:  pair.AccessToken,
		RefreshToken: pair.RefreshToken,
		TokenType:    "Bearer",
		ExpiresIn:    int(pair.AccessTTL.Seconds()),
	})
}

func (h *authHandler) refresh(w http.ResponseWriter, r *http.Request) {
	var req refreshReq
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_body", err.Error())
		return
	}
	pair, err := h.svc.Refresh(r.Context(), req.RefreshToken)
	if err != nil {
		writeDomainError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, tokenPairResp{
		AccessToken:  pair.AccessToken,
		RefreshToken: pair.RefreshToken,
		TokenType:    "Bearer",
		ExpiresIn:    int(pair.AccessTTL.Seconds()),
	})
}

func (h *authHandler) validate(w http.ResponseWriter, r *http.Request) {
	var req validateReq
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_body", err.Error())
		return
	}
	c, err := h.svc.Validate(r.Context(), req.Token)
	if err != nil {
		writeJSON(w, http.StatusOK, validateResp{Valid: false})
		return
	}
	writeJSON(w, http.StatusOK, validateResp{
		Valid:     true,
		UserID:    c.UserID.String(),
		ExpiresAt: c.ExpiresAt.Unix(),
		Scopes:    c.Scopes,
	})
}

// --- helpers ---

func decodeJSON(r *http.Request, v any) error {
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

type apiError struct {
	Error   string `json:"error"`
	Message string `json:"message,omitempty"`
}

func writeError(w http.ResponseWriter, code int, e, msg string) {
	writeJSON(w, code, apiError{Error: e, Message: msg})
}

// writeDomainError мапит доменные ошибки на HTTP-коды без утечек деталей.
func writeDomainError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, domain.ErrEmailTaken):
		writeError(w, http.StatusConflict, "email_taken", "")
	case errors.Is(err, domain.ErrInvalidEmail):
		writeError(w, http.StatusBadRequest, "invalid_email", "")
	case errors.Is(err, domain.ErrWeakPassword):
		writeError(w, http.StatusBadRequest, "weak_password", "")
	case errors.Is(err, domain.ErrInvalidCredentials),
		errors.Is(err, domain.ErrUserNotFound):
		writeError(w, http.StatusUnauthorized, "invalid_credentials", "")
	case errors.Is(err, domain.ErrTokenExpired):
		writeError(w, http.StatusUnauthorized, "token_expired", "")
	case errors.Is(err, domain.ErrTokenRevoked):
		writeError(w, http.StatusUnauthorized, "token_revoked", "")
	case errors.Is(err, domain.ErrTokenInvalid):
		writeError(w, http.StatusUnauthorized, "token_invalid", "")
	default:
		writeError(w, http.StatusInternalServerError, "internal_error", "")
	}
}
