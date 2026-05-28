package ratelimit

import (
    "net/http"
    "net/http/httptest"
    "testing"
)

func TestRateLimiter(t *testing.T) {
    rl := NewRateLimiter(1, 1)

    hits := 0
    handler := rl.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        hits++
        w.WriteHeader(http.StatusOK)
    }))

    // First request should pass
    req := httptest.NewRequest("GET", "/", nil)
    w := httptest.NewRecorder()
    handler.ServeHTTP(w, req)
    if w.Code != http.StatusOK {
        t.Errorf("Expected 200, got %d", w.Code)
    }
    if hits != 1 {
        t.Errorf("Expected 1 hit, got %d", hits)
    }

    // Second request should be rate limited
    w = httptest.NewRecorder()
    handler.ServeHTTP(w, req)
    if w.Code != http.StatusTooManyRequests {
        t.Errorf("Expected 429, got %d", w.Code)
    }
    if hits != 1 {
        t.Errorf("Expected still 1 hit, got %d", hits)
    }
}

func TestRateLimiterDisabled(t *testing.T) {
    rl := NewRateLimiter(0, 0)

    hits := 0
    handler := rl.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        hits++
        w.WriteHeader(http.StatusOK)
    }))

    for i := 0; i < 5; i++ {
        req := httptest.NewRequest("GET", "/", nil)
        w := httptest.NewRecorder()
        handler.ServeHTTP(w, req)
        if w.Code != http.StatusOK {
            t.Errorf("Request %d: Expected 200, got %d", i, w.Code)
        }
    }
    if hits != 5 {
        t.Errorf("Expected 5 hits, got %d", hits)
    }
}