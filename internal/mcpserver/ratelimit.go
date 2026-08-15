package mcpserver

import (
	"sync"
	"time"
)

// pollLimiter rate-limits get_grant polling per agent (section 4.2:
// "Poll volume is rate-limited and logged"). Token bucket, in-memory:
// the durable ledger (I5) covers grant-issuance state; poll limiting is
// an abuse damper whose reset on restart is acceptable and documented.
type pollLimiter struct {
	mu         sync.Mutex
	buckets    map[string]*pollBucket
	perMinute  float64
	burst      float64
	now        func() time.Time
	lastSweep  time.Time
	sweepEvery time.Duration
	maxIdle    time.Duration
}

type pollBucket struct {
	tokens float64
	last   time.Time
}

// newPollLimiter builds a limiter refilling perMinute tokens per minute
// with the given burst. perMinute <= 0 disables limiting entirely.
func newPollLimiter(perMinute float64, burst int) *pollLimiter {
	b := float64(burst)
	if b < 1 {
		b = 1
	}
	return &pollLimiter{
		buckets:    make(map[string]*pollBucket),
		perMinute:  perMinute,
		burst:      b,
		now:        time.Now,
		sweepEvery: 5 * time.Minute,
		maxIdle:    15 * time.Minute,
	}
}

// Allow reports whether one more poll is permitted for key right now.
func (l *pollLimiter) Allow(key string) bool {
	if l.perMinute <= 0 {
		return true
	}
	l.mu.Lock()
	defer l.mu.Unlock()

	now := l.now()
	l.sweepLocked(now)

	b, ok := l.buckets[key]
	if !ok {
		b = &pollBucket{tokens: l.burst, last: now}
		l.buckets[key] = b
	} else {
		elapsed := now.Sub(b.last).Minutes()
		if elapsed > 0 {
			b.tokens += elapsed * l.perMinute
			if b.tokens > l.burst {
				b.tokens = l.burst
			}
			b.last = now
		}
	}
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// sweepLocked drops buckets idle past maxIdle so the map stays bounded
// under agent-id churn. Called with l.mu held.
func (l *pollLimiter) sweepLocked(now time.Time) {
	if now.Sub(l.lastSweep) < l.sweepEvery {
		return
	}
	l.lastSweep = now
	for k, b := range l.buckets {
		if now.Sub(b.last) > l.maxIdle {
			delete(l.buckets, k)
		}
	}
}
