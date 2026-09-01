package eparakstssigner

import (
	"context"

	"go.uber.org/zap"

	"github.com/gmb-lib/go-platform-kit/broker"
)

// logTransport is a broker.Transport that writes published events to the service
// logger. It lets eIDAS-audit (go-eidas-audit signing evidence) emit without a hard
// broker dependency in development; the platform's Transport is service-provided,
// so a real Kafka/NATS transport is injected in production with no code change
// here. PII/secret redaction still applies (platform.Setup), and the broker
// envelope already strips token-shaped attributes.
type logTransport struct{ log *zap.Logger }

// newLogTransport returns a logging broker transport.
func newLogTransport(log *zap.Logger) broker.Transport {
	if log == nil {
		log = zap.NewNop()
	}
	return &logTransport{log: log}
}

// Publish writes the event payload to the logger as an audit_event line.
func (t *logTransport) Publish(_ context.Context, topic, key string, payload []byte) error {
	t.log.Info("audit_event",
		zap.String("topic", topic),
		zap.String("key", key),
		zap.ByteString("event", payload),
	)
	return nil
}
