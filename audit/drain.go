package audit

import (
	"context"
	"time"

	"azugo.io/core"

	"github.com/gmb-lib/go-gdpr-audit/gdpr"
)

// drainable is the shared shutdown contract of the audit clients that buffer
// records/events in a background outbox: a Drain loop and a Close that stops it
// and flushes. Both *gdpr.Client and *eidas.Emitter satisfy it.
type drainable interface {
	Drain(ctx context.Context)
	Close(ctx context.Context) error
}

// drainTask runs a drainable's background outbox delivery as a core.Tasker, so
// buffered records/events deliver in the background and flush on shutdown
// without an App.Start/Stop override.
type drainTask struct {
	name   string
	client drainable
}

// NewDrainTask returns a Tasker that drains the GDPR-audit client's buffered
// access records and flushes them on shutdown.
func NewDrainTask(client *gdpr.Client) core.Tasker {
	return &drainTask{name: "gdpr-audit-drain", client: client}
}

// NewEmitterDrainTask returns a Tasker that drains a buffered audit emitter/client
// (e.g. the eIDAS-audit Emitter) under the given task name, flushing on shutdown.
func NewEmitterDrainTask(name string, client drainable) core.Tasker {
	return &drainTask{name: name, client: client}
}

func (t *drainTask) Name() string { return t.name }

func (t *drainTask) Start(ctx context.Context) error {
	go t.client.Drain(ctx)
	return nil
}

func (t *drainTask) Stop() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = t.client.Close(ctx)
}
