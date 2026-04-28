package httpsrv

import (
	"encoding/json"
	"net/http"

	"github.com/eventflow/auth-service/internal/keystore"
)

// jwksHandler возвращает текущий набор публичных ключей.
//
// Cache-Control: позволяем gateway-ам кешировать JWKS на 5 минут — он сам
// решает, когда подтянуть свежий (например, при unknown-kid).
func jwksHandler(ks *keystore.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "public, max-age=300")
		_ = json.NewEncoder(w).Encode(ks.JWKS())
	}
}
