package api

import (
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// limiterSet is a per-key token bucket group (Rencana V1 §24: rate-limit
// login, reserve, submit, and the public verify endpoint). Keys are an IP for
// unauthenticated routes and an account id for authenticated ones. Idle keys
// are swept so the map does not grow without bound.
type limiterSet struct {
	mu    sync.Mutex
	seen  map[string]*entry
	rps   rate.Limit
	burst int
}

type entry struct {
	lim  *rate.Limiter
	last time.Time
}

func newLimiterSet(perMinute int) *limiterSet {
	ls := &limiterSet{
		seen:  map[string]*entry{},
		rps:   rate.Limit(float64(perMinute) / 60.0),
		burst: max(perMinute/6, 3),
	}
	go ls.sweep()
	return ls
}

func (ls *limiterSet) allow(key string) bool {
	ls.mu.Lock()
	e := ls.seen[key]
	if e == nil {
		e = &entry{lim: rate.NewLimiter(ls.rps, ls.burst)}
		ls.seen[key] = e
	}
	e.last = time.Now()
	ls.mu.Unlock()
	return e.lim.Allow()
}

func (ls *limiterSet) sweep() {
	for range time.Tick(10 * time.Minute) {
		cut := time.Now().Add(-15 * time.Minute)
		ls.mu.Lock()
		for k, e := range ls.seen {
			if e.last.Before(cut) {
				delete(ls.seen, k)
			}
		}
		ls.mu.Unlock()
	}
}

// clientIP is the best-effort remote address. Behind Caddy the first
// X-Forwarded-For hop is the real client; direct connections use RemoteAddr.
func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		first, _, _ := strings.Cut(xff, ",")
		return strings.TrimSpace(first)
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// byIP / byAccount are the two key functions used with limit().
func byIP(r *http.Request) string      { return clientIP(r) }
func byAccount(r *http.Request) string { return claims(r).Sub }

// limit wraps h, rejecting requests over the set's rate with 429.
func (s *Server) limit(ls *limiterSet, key func(*http.Request) string, h http.HandlerFunc) http.HandlerFunc {
	if ls == nil {
		return h
	}
	return func(w http.ResponseWriter, r *http.Request) {
		if !ls.allow(key(r)) {
			w.Header().Set("Retry-After", "60")
			writeErr(w, http.StatusTooManyRequests, "rate limit exceeded, slow down")
			return
		}
		h(w, r)
	}
}
