package middleware

import (
	"net/http"
)

// DisableCSRF is a middleware that disables CSRF checks
// by always allowing the request to proceed
func DisableCSRF(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Skip any CSRF validation and proceed with the request
		next.ServeHTTP(w, r)
	})
}
