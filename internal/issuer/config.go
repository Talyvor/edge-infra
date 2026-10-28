package issuer

import (
	"fmt"
	"os"
	"strings"
	"time"
)

// MaxTokenTTL bounds ISSUER_TOKEN_TTL (B50.8).
const MaxTokenTTL = 24 * time.Hour

// Config is the issuer's runtime configuration, sourced from the environment.
type Config struct {
	ListenAddr  string        // ISSUER_LISTEN_ADDR (default :8081)
	DatabaseURL string        // ISSUER_DATABASE_URL (required)
	IssuerURL   string        // ISSUER_URL — the `iss` claim (required)
	Audience    string        // ISSUER_AUDIENCE — the `aud` claim (required)
	TokenTTL    time.Duration // ISSUER_TOKEN_TTL (default 1h, at most MaxTokenTTL)
	KeysDir     string        // ISSUER_KEYS_DIR — dir of <kid>.pem (required)
	ActiveKID   string        // ISSUER_ACTIVE_KID — signer (required)
	TLSCertFile string        // ISSUER_TLS_CERT (optional)
	TLSKeyFile  string        // ISSUER_TLS_KEY (optional)
	LogLevel    string        // ISSUER_LOG_LEVEL (default info)
	SCIMToken   string        // ISSUER_SCIM_TOKEN — enables /scim/v2 (optional)
	SSO         *SSOConfig    // ISSUER_OIDC_* — enables /sso (optional; nil when unset)
}

// ConfigFromEnv loads and validates the serving configuration. It fails closed
// on any missing required value rather than starting in a degraded state.
func ConfigFromEnv() (*Config, error) {
	required := func(k string) (string, error) {
		v := os.Getenv(k)
		if v == "" {
			return "", fmt.Errorf("missing required env var %s", k)
		}
		return v, nil
	}
	optional := func(k, def string) string {
		if v := os.Getenv(k); v != "" {
			return v
		}
		return def
	}

	cfg := &Config{
		ListenAddr: optional("ISSUER_LISTEN_ADDR", ":8081"),
		LogLevel:   optional("ISSUER_LOG_LEVEL", "info"),
	}

	var err error
	if cfg.DatabaseURL, err = required("ISSUER_DATABASE_URL"); err != nil {
		return nil, err
	}
	if cfg.IssuerURL, err = required("ISSUER_URL"); err != nil {
		return nil, err
	}
	if cfg.Audience, err = required("ISSUER_AUDIENCE"); err != nil {
		return nil, err
	}
	if cfg.KeysDir, err = required("ISSUER_KEYS_DIR"); err != nil {
		return nil, err
	}
	if cfg.ActiveKID, err = required("ISSUER_ACTIVE_KID"); err != nil {
		return nil, err
	}

	ttl := optional("ISSUER_TOKEN_TTL", "1h")
	if cfg.TokenTTL, err = time.ParseDuration(ttl); err != nil {
		return nil, fmt.Errorf("ISSUER_TOKEN_TTL: %w", err)
	}
	// A token cannot be revoked before it expires, so its lifetime is bounded.
	if cfg.TokenTTL <= 0 || cfg.TokenTTL > MaxTokenTTL {
		return nil, fmt.Errorf("ISSUER_TOKEN_TTL must be more than 0 and at most %s (got %s)", MaxTokenTTL, cfg.TokenTTL)
	}

	cfg.TLSCertFile = os.Getenv("ISSUER_TLS_CERT")
	cfg.TLSKeyFile = os.Getenv("ISSUER_TLS_KEY")
	if (cfg.TLSCertFile == "") != (cfg.TLSKeyFile == "") {
		return nil, fmt.Errorf("ISSUER_TLS_CERT and ISSUER_TLS_KEY must be set together")
	}

	cfg.SCIMToken = os.Getenv("ISSUER_SCIM_TOKEN")
	if cfg.SCIMToken != "" && len(cfg.SCIMToken) < 32 {
		return nil, fmt.Errorf("ISSUER_SCIM_TOKEN must be at least 32 characters (got %d)", len(cfg.SCIMToken))
	}

	sso := SSOConfig{
		Issuer:       os.Getenv("ISSUER_OIDC_ISSUER"),
		ClientID:     os.Getenv("ISSUER_OIDC_CLIENT_ID"),
		ClientSecret: os.Getenv("ISSUER_OIDC_CLIENT_SECRET"),
		RedirectURL:  os.Getenv("ISSUER_OIDC_REDIRECT_URL"),
		CAFile:       os.Getenv("ISSUER_OIDC_CA_FILE"),
	}
	if sso.Issuer != "" || sso.ClientID != "" || sso.ClientSecret != "" || sso.RedirectURL != "" {
		if sso.Issuer == "" || sso.ClientID == "" || sso.ClientSecret == "" || sso.RedirectURL == "" {
			return nil, fmt.Errorf("ISSUER_OIDC_ISSUER, ISSUER_OIDC_CLIENT_ID, ISSUER_OIDC_CLIENT_SECRET and ISSUER_OIDC_REDIRECT_URL must be set together")
		}
		if !strings.HasPrefix(sso.Issuer, "https://") || !strings.HasPrefix(sso.RedirectURL, "https://") {
			return nil, fmt.Errorf("ISSUER_OIDC_ISSUER and ISSUER_OIDC_REDIRECT_URL must use https://")
		}
		cfg.SSO = &sso
	}

	return cfg, nil
}
