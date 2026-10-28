package issuer

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// A client that keeps presenting a wrong SCIM token is locked out — even its
// next request with the right token waits — while another IP is unaffected.
func TestSCIMRefusalsLockTheClientIP(t *testing.T) {
	srv := testServer(t, &fakeStore{})
	srv.EnableSCIM(&memUsers{users: map[string]*SCIMUser{}}, testSCIMToken)
	h := srv.Routes()
	call := func(ip, token string) int {
		req := httptest.NewRequest(http.MethodGet, "/scim/v2/Users", nil)
		req.RemoteAddr = ip + ":4000"
		req.Header.Set("Authorization", "Bearer "+token)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Code
	}
	for i := 0; i < 5; i++ {
		if code := call("203.0.113.9", "guess-"+strings.Repeat("x", 32)); code != http.StatusUnauthorized {
			t.Fatalf("guess %d = %d, want 401", i+1, code)
		}
	}
	if code := call("203.0.113.9", testSCIMToken); code != http.StatusTooManyRequests {
		t.Fatalf("after 5 refusals = %d, want 429", code)
	}
	if code := call("198.51.100.7", testSCIMToken); code != http.StatusOK {
		t.Fatalf("another IP = %d, want 200", code)
	}
}

// Forged SSO callbacks (no sign-in started here) lock the client IP before the
// issuer would ever exchange a code with the IdP.
func TestSSOForgedCallbacksLockTheClientIP(t *testing.T) {
	idp := newFakeIdP(t)
	srv := testServer(t, &fakeStore{})
	users := &memUsers{users: map[string]*SCIMUser{}}
	if err := srv.EnableSSO(SSOConfig{
		Issuer: idp.srv.URL, ClientID: "edge", ClientSecret: "s3cret",
		RedirectURL: "https://issuer.example/sso/callback", CAFile: idp.caFile(t),
	}, users); err != nil {
		t.Fatal(err)
	}
	h := srv.Routes()
	code := 0
	for i := 0; i < 6; i++ {
		req := httptest.NewRequest(http.MethodGet, "/sso/callback?code=c&state=forged", nil)
		req.RemoteAddr = "203.0.113.9:4000"
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		code = rec.Code
	}
	if code != http.StatusTooManyRequests {
		t.Fatalf("6th forged callback = %d, want 429", code)
	}
}

// A token lifetime of zero, or above MaxTokenTTL, stops the issuer starting.
func TestTokenTTLIsBounded(t *testing.T) {
	for k, v := range map[string]string{
		"ISSUER_DATABASE_URL": "postgres://x", "ISSUER_URL": "https://issuer.example", "ISSUER_AUDIENCE": "aud",
		"ISSUER_KEYS_DIR": t.TempDir(), "ISSUER_ACTIVE_KID": "k1",
	} {
		t.Setenv(k, v)
	}
	for ttl, ok := range map[string]bool{"1h": true, "24h": true, "0s": false, "-1m": false, "25h": false} {
		t.Setenv("ISSUER_TOKEN_TTL", ttl)
		if _, err := ConfigFromEnv(); (err == nil) != ok {
			t.Errorf("ISSUER_TOKEN_TTL=%s: err = %v, want ok=%v", ttl, err, ok)
		}
	}
}
