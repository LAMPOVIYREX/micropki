package ratelimit

import (
    "log"
    "net/http"
    "sync"

    "golang.org/x/time/rate"
)

type RateLimiter struct {
    limiters sync.Map
    rate     rate.Limit
    burst    int
}

func NewRateLimiter(rps int, burst int) *RateLimiter {
    return &RateLimiter{
        rate:  rate.Limit(rps),
        burst: burst,
    }
}

func (rl *RateLimiter) Middleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        if rl.rate == 0 {
            next.ServeHTTP(w, r)
            return
        }
        ip := r.RemoteAddr
        limiterI, _ := rl.limiters.LoadOrStore(ip, rate.NewLimiter(rl.rate, rl.burst))
        limiter := limiterI.(*rate.Limiter)
        if !limiter.Allow() {
            log.Println("Rate limit exceeded for", ip)
            w.Header().Set("Retry-After", "1")
            http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
            return
        }
        next.ServeHTTP(w, r)
    })
}