package ssplus

import (
	"crypto/sha256"
	"sync"
	"time"
)

const replayRetention = 2*clockWindow + time.Second

type replayBucket struct {
	expires time.Time
	tokens  [][sha256.Size]byte
}

// Expire only elapsed buckets, never scan the live map. Buckets round retention
// up by at most one second. SHA-256 digests avoid retaining both a full IV and a
// per-entry timestamp; this is a local cache key, not a change to authentication.
// No background goroutine or timer survives an idle/closed server.
type replayCache struct {
	mutex   sync.Mutex
	entries map[[sha256.Size]byte]struct{}
	buckets []replayBucket
	head    int
}

func (c *replayCache) remember(iv []byte, now time.Time) bool {
	if len(iv) != IVSize {
		return false
	}
	token := sha256.Sum256(iv)
	c.mutex.Lock()
	defer c.mutex.Unlock()
	for c.head < len(c.buckets) && !now.Before(c.buckets[c.head].expires) {
		for _, expired := range c.buckets[c.head].tokens {
			delete(c.entries, expired)
		}
		c.buckets[c.head] = replayBucket{}
		c.head++
	}
	if c.head > 0 && c.head >= len(c.buckets)/2 {
		remaining := copy(c.buckets, c.buckets[c.head:])
		clear(c.buckets[remaining:])
		c.buckets = c.buckets[:remaining]
		c.head = 0
	}
	if _, exists := c.entries[token]; exists {
		return false
	}
	// Never evict live entries: capacity pressure must not reopen replay windows.
	if len(c.entries) >= maxReplayEntries {
		return false
	}
	if c.entries == nil {
		c.entries = make(map[[sha256.Size]byte]struct{})
	}
	expires := now.Add(replayRetention)
	if len(c.buckets) == 0 || expires.After(c.buckets[len(c.buckets)-1].expires) {
		c.buckets = append(c.buckets, replayBucket{expires: expires.Add(time.Second)})
	}
	// Backwards clock movement joins the last bucket, extending rather than
	// shortening retention and keeping expiration order monotonic.
	bucket := &c.buckets[len(c.buckets)-1]
	bucket.tokens = append(bucket.tokens, token)
	c.entries[token] = struct{}{}
	return true
}
