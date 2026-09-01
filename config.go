package eparakstssigner

import (
	"fmt"
	"net/url"
	"strings"
	"time"

	azugocfg "azugo.io/azugo/config"
	corecfg "azugo.io/core/config"
	"azugo.io/core/validation"
	"github.com/spf13/viper"

	"github.com/gmb-lib/go-authbyte/authclient"
	"github.com/gmb-lib/go-gdpr-audit/gdpr"
	pkconfig "github.com/gmb-lib/go-platform-kit/config"

	"github.com/signbyte/eparaksts-signer/entrust"
	"github.com/signbyte/eparaksts-signer/signing"
)

// Configuration is the eParaksts Signing Service configuration: the platform base
// config, the inbound go-authbyte DPoP validation config, the upstream platform
// (TrustedX + CSC) + SignAPI settings, the job store, and the three audit regimes.
type Configuration struct {
	*pkconfig.BaseConfiguration `mapstructure:",squash"`

	// Auth is the inbound DPoP validation config (AUTH_ISSUER_URL /
	// SERVICE_AUDIENCE=svc:eparaksts-signer / …).
	Auth *authclient.Configuration `mapstructure:"auth"`

	// UploadHardening runs the document gate on every uploaded file BEFORE it
	// is forwarded upstream: validate/archive uploads must be a signed PDF or
	// a signed, well-formed ASiC-E; signing (prepare) uploads may be any
	// format, but content that claims or appears to be PDF/ASiC-E must parse.
	// Default TRUE — a standalone deployment is protected out of the box; a
	// deployment fronted by an already-gated edge sets it false to avoid
	// checking the same bytes twice.
	UploadHardening bool `mapstructure:"upload_hardening"`
	// MaxUploadBytes caps each uploaded file (the per-file limit of the
	// upstream signing service; the whole request is additionally bounded by
	// SERVER_MAX_REQUEST_BODY_SIZE).
	MaxUploadBytes int64 `mapstructure:"max_upload_bytes" validate:"required,gt=0"`

	// RedisURL backs the job store + work queue (redis://host:port/db).
	RedisURL string `mapstructure:"redis_url" validate:"required,url"`
	// JobTTL bounds a job's lifetime (and the short-lived upstream tokens inside it).
	JobTTL time.Duration `mapstructure:"job_ttl" validate:"required,gt=0"`

	// SignAPIBaseURL is the eParaksts SignAPI base (the shared document spine).
	SignAPIBaseURL string `mapstructure:"signapi_base_url" validate:"omitempty,url"`

	// --- TrustedX surface (mobile / eidScan / cloudEseal) ---
	TXBaseURL       string `mapstructure:"tx_base_url" validate:"omitempty,url"`
	TXASPath        string `mapstructure:"tx_as_path"`
	TXClientID      string `mapstructure:"tx_client_id"`
	TXClientSecret  string `mapstructure:"tx_client_secret"`
	TXRedirectURI   string `mapstructure:"tx_redirect_uri" validate:"omitempty,url"`
	TXACRMobile     string `mapstructure:"tx_acr_mobile"`
	TXACREIDScan    string `mapstructure:"tx_acr_eidscan"`
	TXACRCloudEseal string `mapstructure:"tx_acr_cloudeseal"`

	// --- CSC API layer (csc) — partly open (items E/F/Cert) ---
	CSCBaseURL      string `mapstructure:"csc_base_url" validate:"omitempty,url"`
	CSCClientID     string `mapstructure:"csc_client_id"`
	CSCClientSecret string `mapstructure:"csc_client_secret"`
	// CSCAuthCert is the interim config-supplied finalize authCertificate for the
	// csc flow ONLY (base64-DER) — every other use case sends the signed-in
	// user's own authentication certificate with the request.
	CSCAuthCert string `mapstructure:"csc_auth_cert"`

	// Identity fetch retry (sign_identities materialize asynchronously).
	IdentityFetchRetries int           `mapstructure:"tx_identity_fetch_retries"`
	IdentityFetchDelay   time.Duration `mapstructure:"tx_identity_fetch_delay"`

	// eidScan device-push timing.
	EIDScanPollInterval time.Duration `mapstructure:"eidscan_poll_interval"`
	EIDScanDeadline     time.Duration `mapstructure:"eidscan_sign_deadline"`

	// DefaultSignatureQualifier when the caller omits one.
	DefaultSignatureQualifier string `mapstructure:"default_signature_qualifier"`

	// --- eIDAS-audit (eIDAS signing evidence) ---
	EIDASAuditTopic string `mapstructure:"eidas_audit_topic"`
	// EidasAuditOutboxDir, when set, makes eIDAS-audit emission durable +
	// non-blocking: signing-evidence events spool to this directory and a
	// background drainer publishes them (so the request path never blocks on NATS
	// and evidence survives a broker outage / restart). Unset → synchronous
	// publish (dev/test). MUST differ from AccessAuditOutboxDir — two FileOutbox
	// spools must never share a directory.
	EidasAuditOutboxDir string `mapstructure:"eidas_audit_outbox_dir"`

	// --- GDPR-audit (GDPR personal-data access) → access-audit (optional) ---
	AccessAuditURL       string `mapstructure:"access_audit_url" validate:"omitempty,url"`
	AccessAuditAudience  string `mapstructure:"access_audit_audience"`
	AccessAuditScope     string `mapstructure:"access_audit_scope"`
	AccessAuditOutboxDir string `mapstructure:"access_audit_outbox_dir"`
	AuditClientID        string `mapstructure:"audit_client_id"`
	AuditClientSecret    string `mapstructure:"audit_client_secret"`
	AuditIssuerURL       string `mapstructure:"audit_issuer_url" validate:"omitempty,url"`
	PseudonymKey         string `mapstructure:"audit_subject_pseudonym_key"`
}

// NewConfiguration returns the configuration skeleton for binding.
func NewConfiguration() *Configuration {
	return &Configuration{BaseConfiguration: pkconfig.New()}
}

// ServerCore returns the embedded azugo configuration.
func (c *Configuration) ServerCore() *azugocfg.Configuration {
	return c.Configuration
}

// Bind registers defaults and environment bindings.
func (c *Configuration) Bind(_ string, v *viper.Viper) {
	c.BaseConfiguration.Bind("", v)
	c.Auth = azugocfg.Bind(c.Auth, "auth", v)

	// Job store.
	v.SetDefault("job_ttl", time.Hour)
	_ = v.BindEnv("redis_url", "REDIS_URL")
	_ = v.BindEnv("job_ttl", "JOB_TTL")

	// Dev-only user-token concession (off by default).
	// The document gate — on by default; MAX_UPLOAD_BYTES matches the
	// upstream per-file limit. The server-level body cap default is raised to
	// fit a multi-file signing preparation (SERVER_MAX_REQUEST_BODY_SIZE
	// still overrides it).
	v.SetDefault("upload_hardening", true)
	v.SetDefault("max_upload_bytes", 25*1024*1024) // 25 MiB
	v.SetDefault("server.max_request_body_size", 64*1024*1024)
	_ = v.BindEnv("upload_hardening", "UPLOAD_HARDENING")
	_ = v.BindEnv("max_upload_bytes", "MAX_UPLOAD_BYTES")

	// SignAPI + upstream surfaces.
	v.SetDefault("tx_as_path", "/trustedx-authserver/oauth/lvrtc-eipsign-as")
	v.SetDefault("tx_acr_mobile", "urn:eparaksts:authentication:flow:mobileid")
	v.SetDefault("tx_acr_eidscan", "urn:eparaksts:authentication:flow:mobile-eid")
	v.SetDefault("tx_acr_cloudeseal", "urn:eparaksts:authentication:flow:mobileid")
	v.SetDefault("tx_identity_fetch_retries", 5)
	v.SetDefault("tx_identity_fetch_delay", 2*time.Second)
	v.SetDefault("eidscan_poll_interval", 2*time.Second)
	v.SetDefault("eidscan_sign_deadline", 120*time.Second)
	v.SetDefault("default_signature_qualifier", "eu_eidas_qes")
	loadSecret(v, "tx_client_secret", "EPARAKSTS_CLIENT_SECRET")
	loadSecret(v, "csc_client_secret", "CSC_CLIENT_SECRET")
	loadSecret(v, "csc_auth_cert", "CSC_AUTH_CERT")
	_ = v.BindEnv("signapi_base_url", "SIGNAPI_BASE_URL")
	_ = v.BindEnv("tx_base_url", "TX_BASE_URL")
	_ = v.BindEnv("tx_as_path", "TX_AS_PATH")
	// TrustedX client credentials are the SAME eParaksts demo client authbyte-core
	// logs in with, so they read the shared EPARAKSTS_CLIENT_* env (one secret,
	// reused). Internal keys stay tx_* (this is the TrustedX surface).
	_ = v.BindEnv("tx_client_id", "EPARAKSTS_CLIENT_ID")
	_ = v.BindEnv("tx_client_secret", "EPARAKSTS_CLIENT_SECRET")
	_ = v.BindEnv("tx_redirect_uri", "TX_REDIRECT_URI")
	_ = v.BindEnv("tx_acr_mobile", "TX_ACR_MOBILE")
	_ = v.BindEnv("tx_acr_eidscan", "TX_ACR_EIDSCAN")
	_ = v.BindEnv("tx_acr_cloudeseal", "TX_ACR_CLOUDESEAL")
	_ = v.BindEnv("csc_base_url", "CSC_BASE_URL")
	_ = v.BindEnv("csc_client_id", "CSC_CLIENT_ID")
	_ = v.BindEnv("csc_client_secret", "CSC_CLIENT_SECRET")
	_ = v.BindEnv("csc_auth_cert", "CSC_AUTH_CERT")
	_ = v.BindEnv("tx_identity_fetch_retries", "TX_IDENTITY_FETCH_RETRIES")
	_ = v.BindEnv("tx_identity_fetch_delay", "TX_IDENTITY_FETCH_DELAY")
	_ = v.BindEnv("eidscan_poll_interval", "EIDSCAN_POLL_INTERVAL")
	_ = v.BindEnv("eidscan_sign_deadline", "EIDSCAN_SIGN_DEADLINE")
	_ = v.BindEnv("default_signature_qualifier", "DEFAULT_SIGNATURE_QUALIFIER")

	// eIDAS-audit topic + (optional) durable outbox.
	v.SetDefault("eidas_audit_topic", "audit.signing")
	_ = v.BindEnv("eidas_audit_topic", "EIDAS_AUDIT_TOPIC")
	_ = v.BindEnv("eidas_audit_outbox_dir", "EIDAS_AUDIT_OUTBOX_DIR")

	// GDPR-audit — off until ACCESS_AUDIT_URL is set.
	v.SetDefault("access_audit_audience", "svc:access-audit")
	v.SetDefault("access_audit_scope", "access-audit:write")
	v.SetDefault("audit_client_id", "svc:eparaksts-signer")
	loadSecret(v, "audit_client_secret", "AUDIT_CLIENT_SECRET")
	loadSecret(v, "audit_subject_pseudonym_key", "AUDIT_SUBJECT_PSEUDONYM_KEY")
	_ = v.BindEnv("access_audit_url", "ACCESS_AUDIT_URL")
	_ = v.BindEnv("access_audit_audience", "ACCESS_AUDIT_AUDIENCE")
	_ = v.BindEnv("access_audit_scope", "ACCESS_AUDIT_SCOPE")
	_ = v.BindEnv("access_audit_outbox_dir", "ACCESS_AUDIT_OUTBOX_DIR")
	_ = v.BindEnv("audit_client_id", "AUDIT_CLIENT_ID")
	_ = v.BindEnv("audit_client_secret", "AUDIT_CLIENT_SECRET")
	_ = v.BindEnv("audit_issuer_url", "AUDIT_ISSUER_URL")
	_ = v.BindEnv("audit_subject_pseudonym_key", "AUDIT_SUBJECT_PSEUDONYM_KEY")
}

// Validate validates the full configuration tree.
func (c *Configuration) Validate(valid *validation.Validate) error {
	if err := c.BaseConfiguration.Validate(valid); err != nil {
		return err
	}
	if err := c.Auth.Validate(valid); err != nil {
		return err
	}
	// The eIDAS-audit and GDPR-audit durable outboxes are independent FileOutbox
	// spools; they must never share a directory (cross-consumption would corrupt
	// both — the GDPR drainer would dequeue an eIDAS envelope and POST it to
	// access-audit, and vice-versa).
	if d := strings.TrimSpace(c.EidasAuditOutboxDir); d != "" && d == strings.TrimSpace(c.AccessAuditOutboxDir) {
		return fmt.Errorf("eparaksts-signer: EIDAS_AUDIT_OUTBOX_DIR and ACCESS_AUDIT_OUTBOX_DIR must differ (both are %q)", d)
	}
	return valid.Struct(c)
}

// AccessAuditEnabled reports whether GDPR-audit is wired.
func (c *Configuration) AccessAuditEnabled() bool {
	return strings.TrimSpace(c.AccessAuditURL) != ""
}

// DefaultCallbackPath is the OAuth callback path when TXRedirectURI is unset.
const DefaultCallbackPath = "/api/v1/signatures/callback"

// CallbackPath is the path the browser OAuth callback is mounted at. It is
// DERIVED from TXRedirectURI's path, so registering an already-allowed redirect
// (e.g. https://host/Sign/Complete) just works — set TX_REDIRECT_URI and the
// callback handler moves with it. Falls back to DefaultCallbackPath when
// TXRedirectURI is empty or has no path (e.g. eid-only deployments).
func (c *Configuration) CallbackPath() string {
	if strings.TrimSpace(c.TXRedirectURI) == "" {
		return DefaultCallbackPath
	}
	u, err := url.Parse(c.TXRedirectURI)
	if err != nil || u.Path == "" {
		return DefaultCallbackPath
	}
	return u.Path
}

// EntrustConfig builds the upstream platform client config.
func (c *Configuration) EntrustConfig() entrust.Config {
	return entrust.Config{
		BaseURL:              c.TXBaseURL,
		ASPath:               c.TXASPath,
		ClientID:             c.TXClientID,
		ClientSecret:         c.TXClientSecret,
		RedirectURI:          c.TXRedirectURI,
		ACRMobile:            c.TXACRMobile,
		ACREIDScan:           c.TXACREIDScan,
		ACRCloudEseal:        c.TXACRCloudEseal,
		CSCBaseURL:           c.CSCBaseURL,
		CSCClientID:          c.CSCClientID,
		CSCClientSecret:      c.CSCClientSecret,
		IdentityFetchRetries: c.IdentityFetchRetries,
		IdentityFetchDelay:   c.IdentityFetchDelay,
	}
}

// OrchestratorConfig builds the orchestrator config.
func (c *Configuration) OrchestratorConfig() signing.Config {
	return signing.Config{
		DefaultSignatureQualifier: c.DefaultSignatureQualifier,
		EIDScanPollInterval:       c.EIDScanPollInterval,
		EIDScanDeadline:           c.EIDScanDeadline,
		CSCAuthCert:               c.CSCAuthCert,
	}
}

// auditIssuer returns the issuer base for the outbound audit token mint.
func (c *Configuration) auditIssuer() string {
	if u := strings.TrimSpace(c.AuditIssuerURL); u != "" {
		return u
	}
	return c.Auth.IssuerURL
}

// AuditAuthClientConfig builds the OUTBOUND auth-client config for the GDPR-audit
// poster: it reuses the inbound Auth settings and adds this service's
// client-credentials + the (optional) issuer override.
func (c *Configuration) AuditAuthClientConfig() *authclient.Configuration {
	cfg := *c.Auth // copy the validated inbound config
	cfg.IssuerURL = c.auditIssuer()
	cfg.ServiceClientID = c.AuditClientID
	cfg.ServiceClientSecret = c.AuditClientSecret
	return &cfg
}

// GDPRConfig builds the go-gdpr-audit client configuration.
func (c *Configuration) GDPRConfig() gdpr.Configuration {
	return gdpr.Configuration{
		Endpoint:         c.AccessAuditURL,
		Audience:         c.AccessAuditAudience,
		Scope:            c.AccessAuditScope,
		Timeout:          gdpr.DefaultTimeout,
		OutboxCapacity:   gdpr.DefaultOutboxCapacity,
		MaxRetries:       gdpr.DefaultMaxRetries,
		RetryBackoff:     gdpr.DefaultRetryBackoff,
		BreakerThreshold: gdpr.DefaultBreakerThreshold,
		BreakerCooldown:  gdpr.DefaultBreakerCooldown,
	}
}

// PseudonymKeyBytes returns the raw HMAC pseudonym key bytes.
func (c *Configuration) PseudonymKeyBytes() []byte { return []byte(c.PseudonymKey) }

// loadSecret resolves a secret from the secret store (Vault agent → <NAME>_FILE)
// and registers it as a default so an explicit env value still overrides it.
func loadSecret(v *viper.Viper, key, name string) {
	if secret, err := corecfg.LoadRemoteSecret(name); err == nil && secret != "" {
		v.SetDefault(key, secret)
	}
}
