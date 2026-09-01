// Package eparakstssigner is the eParaksts Signing Service: a unified signing
// provider over the eParaksts/Entrust family (the CSC API layer + the TrustedX
// surface) plus the local eID card, fronting the eParaksts SignAPI packaging
// spine. It is a stateless coordinator — it holds no document bytes (SignAPI
// storage does), packages nothing itself (SignAPI/DSS does), and performs no raw
// signature (Entrust HSM / the local card does); it owns the job lifecycle and
// the SigningFlow seam.
//
// All cross-cutting concerns (logging + redaction, OpenTelemetry tracing,
// correlation) come from go-platform-kit's platform.Setup — never wired
// per-service.
package eparakstssigner

import (
	"context"
	"fmt"
	"time"

	"azugo.io/azugo"
	"azugo.io/azugo/server"
	"github.com/redis/go-redis/v9"
	"github.com/spf13/cobra"
	"go.uber.org/zap"

	"github.com/gmb-lib/go-authbyte/authclient"
	"github.com/gmb-lib/go-eidas-audit/eidas"
	"github.com/gmb-lib/go-gdpr-audit/gdpr"
	"github.com/gmb-lib/go-platform-kit/broker"
	"github.com/gmb-lib/go-platform-kit/broker/natsbroker"
	"github.com/gmb-lib/go-platform-kit/platform"
	"github.com/gmb-lib/go-sec-events/secevents"

	"github.com/signbyte/eparaksts-signer/audit"
	"github.com/signbyte/eparaksts-signer/entrust"
	"github.com/signbyte/eparaksts-signer/job"
	"github.com/signbyte/eparaksts-signer/signapi"
	"github.com/signbyte/eparaksts-signer/signing"
)

// App is the eParaksts Signing Service application container.
type App struct {
	*azugo.App

	config *Configuration

	redis        redis.UniversalClient
	jobs         *job.Store
	entrust      *entrust.Client
	signapi      *signapi.Client
	orchestrator *signing.Orchestrator

	authClient *authclient.Client
	authMW     azugo.RequestHandlerFunc

	// natsConn is the broker connection backing the eIDAS-audit transport; held
	// so Stop can drain + close it after the outbox flush.
	natsConn *natsbroker.Conn

	// Audit: eIDAS-audit + NIS2-audit (security) always; GDPR-audit +
	// its outbound auth-client are set only when access-audit is configured.
	auditClient *authclient.Client
	gdprAudit   *gdpr.Client
	audit       *audit.Recorder
}

// New constructs the application.
func New(cmd *cobra.Command, version string) (*App, error) {
	config := NewConfiguration()

	a, err := server.New(cmd, server.Options{
		AppName:       "eParaksts Signing Service",
		AppVer:        version,
		Configuration: config,
	})
	if err != nil {
		return nil, err
	}

	app := &App{App: a, config: config}
	if err := app.init(); err != nil {
		return nil, err
	}
	return app, nil
}

func (a *App) init() error {
	cfg := a.config

	// Platform glue FIRST: logging + redaction, OpenTelemetry tracing, correlation.
	if err := platform.Setup(a.App, platform.Options{Config: cfg.BaseConfiguration}); err != nil {
		return err
	}

	// Job store (Redis) + work queue.
	opts, err := redis.ParseURL(cfg.RedisURL)
	if err != nil {
		return fmt.Errorf("eparaksts-signer: invalid REDIS_URL: %w", err)
	}
	a.redis = redis.NewClient(opts)
	a.jobs = job.New(a.redis, cfg.JobTTL)

	// Upstream platform client + SignAPI client (SignAPI authenticates with the
	// TrustedX introspect token).
	a.entrust = entrust.New(cfg.EntrustConfig(), a.Log())
	a.signapi = signapi.New(cfg.SignAPIBaseURL, a.entrust.IntrospectToken, a.Log())

	// Orchestrator + background signing worker.
	a.orchestrator = signing.New(a.jobs, a.signapi, a.entrust, cfg.OrchestratorConfig(), a.Log())
	if err := a.AddTask(signing.NewWorker(a.orchestrator)); err != nil {
		return fmt.Errorf("eparaksts-signer: worker task: %w", err)
	}

	// Inbound service authentication (go-authbyte DPoP): callers present
	// svc:eparaksts-signer service tokens (the delegated on-behalf tokens included).
	a.authClient, err = authclient.New(cfg.Auth)
	if err != nil {
		return fmt.Errorf("eparaksts-signer: auth client: %w", err)
	}
	a.authMW = a.authClient.Authenticate()

	// Audit. eIDAS-audit (eIDAS signing evidence) over the broker; NIS2-audit (NIS2
	// security) via the log sink → SIEM; GDPR-audit (GDPR access) when configured.
	// eIDAS-audit publishes to NATS JetStream via the shared go-platform-kit transport
	// (broker/natsbroker) when BROKER_URL is set — the eidas-audit sink consumes
	// audit.signing into the hash-chained eidas_audit store. Without BROKER_URL it
	// falls back to the dev log transport (events are NOT durably stored).
	var auditTransport broker.Transport
	if cfg.Broker != nil && cfg.Broker.URL != "" {
		conn, err := natsbroker.Connect(natsbroker.Config{
			URL:     cfg.Broker.URL,
			TLSCert: cfg.Broker.TLSCert,
			TLSKey:  cfg.Broker.TLSKey,
			TLSCA:   cfg.Broker.TLSCA,
			Name:    cfg.ServiceName,
		})
		if err != nil {
			return fmt.Errorf("eparaksts-signer: broker connect: %w", err)
		}
		a.natsConn = conn
		auditTransport = natsbroker.NewTransport(conn)
		a.Log().Info("eIDAS-audit audit → NATS JetStream",
			zap.String("broker_url", cfg.Broker.URL),
			zap.String("topic", cfg.EIDASAuditTopic))
	} else {
		auditTransport = newLogTransport(a.Log())
		a.Log().Warn("BROKER_URL unset — eIDAS-audit audit events go to the dev log transport only (NOT durably stored); set BROKER_URL to publish to the eidas-audit sink")
	}

	// eIDAS-audit signing-evidence emission. With EIDAS_AUDIT_OUTBOX_DIR set it is
	// durable + non-blocking: Emit spools the (stamped) event to disk and returns,
	// and the drain task below publishes it in the background + flushes on
	// shutdown — so a broker hiccup never adds request latency nor silently drops
	// the hash-chained legal evidence. Unset → synchronous publish (dev/test).
	eidasPub := broker.NewPublisher(auditTransport, cfg.ServiceName)
	var eidasOutbox eidas.Outbox
	if dir := cfg.EidasAuditOutboxDir; dir != "" {
		ob, err := eidas.NewFileOutbox(dir, eidas.DefaultOutboxCapacity)
		if err != nil {
			return fmt.Errorf("eparaksts-signer: eidas-audit outbox: %w", err)
		}
		eidasOutbox = ob
		a.Log().Info("eIDAS-audit emission is durable (non-blocking outbox)", zap.String("outbox_dir", dir))
	}
	eidasEmitter := eidas.New(eidasPub, cfg.EIDASAuditTopic, eidas.Options{Outbox: eidasOutbox, Logger: a.Log()})
	if eidasOutbox != nil {
		if err := a.AddTask(audit.NewEmitterDrainTask("eidas-audit-drain", eidasEmitter)); err != nil {
			return fmt.Errorf("eparaksts-signer: eidas drain task: %w", err)
		}
	}
	secEmitter := secevents.NewEmitter(secevents.NewLogSink())

	var (
		psn *audit.Pseudonymizer
		gc  *gdpr.Client
	)
	if cfg.AccessAuditEnabled() {
		psn, err = audit.NewPseudonymizer(cfg.PseudonymKeyBytes())
		if err != nil {
			return fmt.Errorf("eparaksts-signer: audit pseudonym key (set AUDIT_SUBJECT_PSEUDONYM_KEY when ACCESS_AUDIT_URL is set): %w", err)
		}

		oc, err := authclient.New(cfg.AuditAuthClientConfig())
		if err != nil {
			return fmt.Errorf("eparaksts-signer: audit auth client: %w", err)
		}
		a.auditClient = oc

		var outbox gdpr.Outbox
		if dir := cfg.AccessAuditOutboxDir; dir != "" {
			ob, err := gdpr.NewFileOutbox(dir, gdpr.DefaultOutboxCapacity)
			if err != nil {
				return fmt.Errorf("eparaksts-signer: audit outbox: %w", err)
			}
			outbox = ob
		}

		gc, err = gdpr.New(
			cfg.GDPRConfig(),
			newAccessAuditPoster(oc, cfg.AccessAuditURL, cfg.AccessAuditAudience, cfg.AccessAuditScope),
			gdpr.Options{Outbox: outbox, Logger: a.Log()},
		)
		if err != nil {
			return fmt.Errorf("eparaksts-signer: gdpr-audit client: %w", err)
		}
		a.gdprAudit = gc

		if err := a.AddTask(audit.NewDrainTask(gc)); err != nil {
			return fmt.Errorf("eparaksts-signer: gdpr drain task: %w", err)
		}
	} else {
		a.Log().Warn("ACCESS_AUDIT_URL not set — GDPR (GDPR-audit) access records will NOT be posted (development); eIDAS-audit signing evidence + NIS2-audit security telemetry still emit")
	}

	a.audit = audit.New(eidasEmitter, secEmitter, gc, psn, a.Log())

	return nil
}

// Start pings the job store (best effort) and starts the server + tasks.
func (a *App) Start() error {
	ctx, cancel := context.WithTimeout(a.BackgroundContext(), 5*time.Second)
	defer cancel()
	if err := a.jobs.Ping(ctx); err != nil {
		a.Log().Warn("redis not reachable at startup — job store / signing degraded", zap.Error(err))
	}
	return a.App.Start()
}

// Stop releases the Redis client, then stops the server (tasks are stopped by the
// app lifecycle), then drains + closes the broker connection. Ordering matters:
// a.App.Stop() runs the drain tasks' Stop() — flushing the eIDAS/GDPR outboxes —
// while the broker connection is still live; only then do we drain + close it.
func (a *App) Stop() {
	if a.redis != nil {
		_ = a.redis.Close()
	}
	a.App.Stop()
	a.natsConn.Close() // nil-safe; drains in-flight publishes after the outbox flush
}

// Config returns the loaded configuration.
func (a *App) Config() *Configuration {
	if a.config == nil || !a.config.Ready() {
		panic("configuration is not loaded")
	}
	return a.config
}

// Orchestrator returns the signing orchestrator.
func (a *App) Orchestrator() *signing.Orchestrator { return a.orchestrator }

// Audit returns the audit recorder (eIDAS-audit + C always; GDPR-audit when configured).
func (a *App) Audit() *audit.Recorder { return a.audit }

// AuthMiddleware returns the inbound service-authentication middleware.
func (a *App) AuthMiddleware() azugo.RequestHandlerFunc { return a.authMW }

// CallbackPath is the path the public OAuth callback handler is mounted at
// (derived from TX_REDIRECT_URI; default /api/v1/signatures/callback).
func (a *App) CallbackPath() string { return a.config.CallbackPath() }

// SetAuthMiddleware overrides the inbound auth middleware (test use only).
func (a *App) SetAuthMiddleware(mw azugo.RequestHandlerFunc) { a.authMW = mw }
