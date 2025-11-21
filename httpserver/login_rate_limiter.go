package httpserver

import (
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// LoginRateLimiter manages rate limiting for login attempts per IP address
type LoginRateLimiter struct {
	limiters map[string]*rate.Limiter
	mu       sync.Mutex
	rate     rate.Limit // requests per second
	burst    int        // maximum burst size
}

// NewLoginRateLimiter creates a new login rate limiter
// rate: maximum requests per second per IP
// burst: maximum burst size per IP
func NewLoginRateLimiter(r rate.Limit, b int) *LoginRateLimiter {
	return &LoginRateLimiter{
		limiters: make(map[string]*rate.Limiter),
		rate:     r,
		burst:    b,
	}
}

// getLimiter returns the rate limiter for a given IP address
func (l *LoginRateLimiter) getLimiter(ip string) *rate.Limiter {
	l.mu.Lock()
	defer l.mu.Unlock()

	limiter, exists := l.limiters[ip]
	if !exists {
		limiter = rate.NewLimiter(l.rate, l.burst)
		l.limiters[ip] = limiter
		
		// Clean up old limiters after 1 hour of inactivity
		go func() {
			time.Sleep(1 * time.Hour)
			l.mu.Lock()
			delete(l.limiters, ip)
			l.mu.Unlock()
		}()
	}

	return limiter
}

// Allow checks if a login attempt from the given IP is allowed
func (l *LoginRateLimiter) Allow(ip string) bool {
	limiter := l.getLimiter(ip)
	return limiter.Allow()
}
