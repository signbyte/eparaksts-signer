package job

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// ErrNotFound is returned when a job (or state mapping) is absent or expired.
var ErrNotFound = errors.New("job: not found")

// Key prefixes / the work queue list key.
const (
	keyJob   = "job:"   // job:{jobId}            -> Job JSON
	keyState = "state:" // state:{oauthState}     -> jobId (callback correlation)
	keyQueue = "signer:work"
)

// Store persists jobs in Redis and drives the background work queue. It mirrors
// the authbyte-core session.Store pattern (JSON values, TTL-bound, atomic
// single-use consumption where needed).
type Store struct {
	c   redis.UniversalClient
	ttl time.Duration
}

// New creates a job store. ttl is the per-job lifetime (≤1h for csc; bounds the
// short-lived upstream tokens that live inside the job).
func New(c redis.UniversalClient, ttl time.Duration) *Store {
	if ttl <= 0 {
		ttl = time.Hour
	}
	return &Store{c: c, ttl: ttl}
}

// Save writes the job and (re)points its OAuth-state index, both at the job TTL.
func (s *Store) Save(ctx context.Context, j *Job) error {
	b, err := json.Marshal(j)
	if err != nil {
		return err
	}
	if err := s.c.Set(ctx, keyJob+j.JobID, b, s.ttl).Err(); err != nil {
		return fmt.Errorf("job: save: %w", err)
	}
	if j.OAuthState != "" {
		if err := s.c.Set(ctx, keyState+j.OAuthState, j.JobID, s.ttl).Err(); err != nil {
			return fmt.Errorf("job: save state index: %w", err)
		}
	}
	return nil
}

// Load reads a job by id.
func (s *Store) Load(ctx context.Context, jobID string) (*Job, error) {
	b, err := s.c.Get(ctx, keyJob+jobID).Bytes()
	if errors.Is(err, redis.Nil) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("job: load: %w", err)
	}
	var j Job
	if err := json.Unmarshal(b, &j); err != nil {
		return nil, err
	}
	return &j, nil
}

// LoadByState resolves a job from an OAuth `state` value (callback correlation).
func (s *Store) LoadByState(ctx context.Context, state string) (*Job, error) {
	id, err := s.c.Get(ctx, keyState+state).Result()
	if errors.Is(err, redis.Nil) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("job: load by state: %w", err)
	}
	return s.Load(ctx, id)
}

// ClearState removes the OAuth-state index entry (single-use; call once the
// state has been consumed so a replayed callback cannot reuse it).
func (s *Store) ClearState(ctx context.Context, state string) {
	if state == "" {
		return
	}
	_ = s.c.Del(ctx, keyState+state).Err()
}

// Delete removes the job and any state index it carries.
func (s *Store) Delete(ctx context.Context, j *Job) error {
	if j.OAuthState != "" {
		_ = s.c.Del(ctx, keyState+j.OAuthState).Err()
	}
	return s.c.Del(ctx, keyJob+j.JobID).Err()
}

// EnqueueWork pushes a job id onto the background signing queue (the worker
// BRPOPs it). Jobs are resumable from Redis, so a dropped/rescheduled item is
// safe to re-process.
func (s *Store) EnqueueWork(ctx context.Context, jobID string) error {
	return s.c.LPush(ctx, keyQueue, jobID).Err()
}

// DequeueWork blocks up to timeout for the next queued job id. It returns
// ErrNotFound on timeout so the caller can loop and re-check for shutdown.
func (s *Store) DequeueWork(ctx context.Context, timeout time.Duration) (string, error) {
	res, err := s.c.BRPop(ctx, timeout, keyQueue).Result()
	if errors.Is(err, redis.Nil) {
		return "", ErrNotFound
	}
	if err != nil {
		return "", err
	}
	// BRPop returns [key, value].
	if len(res) != 2 {
		return "", ErrNotFound
	}
	return res[1], nil
}

// Ping verifies connectivity (readiness probe).
func (s *Store) Ping(ctx context.Context) error {
	if err := s.c.Ping(ctx).Err(); err != nil {
		return fmt.Errorf("job: redis ping: %w", err)
	}
	return nil
}
