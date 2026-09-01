package signing

import (
	"context"
	"errors"
	"time"

	"azugo.io/core"
	"go.uber.org/zap"

	"github.com/signbyte/eparaksts-signer/job"
)

// worker is the background signing worker: it BRPOPs job ids off the Redis work
// queue and runs RunJob for each, driving remote flows (and eid finalize) to
// completion. It implements core.Tasker so it starts/stops with the app. Jobs
// are Redis-resumable, so a dropped item is safe to re-process and a graceful
// shutdown loses nothing.
type worker struct {
	o    *Orchestrator
	log  *zap.Logger
	stop chan struct{}
	done chan struct{}
}

// NewWorker returns the background signing worker as a core.Tasker.
func NewWorker(o *Orchestrator) core.Tasker {
	return &worker{o: o, log: o.log}
}

func (w *worker) Name() string { return "signing-worker" }

func (w *worker) Start(ctx context.Context) error {
	w.stop = make(chan struct{})
	w.done = make(chan struct{})
	go w.run(ctx)
	return nil
}

func (w *worker) Stop() {
	if w.stop != nil {
		close(w.stop)
		<-w.done
	}
}

func (w *worker) run(ctx context.Context) {
	defer close(w.done)
	for {
		select {
		case <-w.stop:
			return
		case <-ctx.Done():
			return
		default:
		}

		// Block up to 5s for the next job so shutdown stays responsive.
		jobID, err := w.o.Store().DequeueWork(ctx, 5*time.Second)
		if err != nil {
			if errors.Is(err, job.ErrNotFound) {
				// Empty queue (BRPOP timeout) — loop and re-check immediately.
				continue
			}
			// A real Redis error (e.g. transient outage) — back off so we don't
			// busy-spin until it recovers.
			select {
			case <-w.stop:
				return
			case <-ctx.Done():
				return
			case <-time.After(time.Second):
			}
			continue
		}
		w.o.RunJob(ctx, jobID)
	}
}
