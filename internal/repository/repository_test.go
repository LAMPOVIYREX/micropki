package repository

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"micropki/internal/logger"
)

func TestNewServer(t *testing.T) {
	log, _ := logger.NewLogger("")
	config := &ServerConfig{
		DBPath:  ":memory:",
		CertDir: t.TempDir(),
		Host:    "127.0.0.1",
		Port:    0,
	}
	server, err := NewServer(config, log)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}
	if server == nil {
		t.Error("Server is nil")
	}
	_ = server.Close()
	_ = server.Stop()
}

func TestHealthEndpoint(t *testing.T) {
	log, _ := logger.NewLogger("")
	config := &ServerConfig{DBPath: ":memory:", CertDir: t.TempDir()}
	server, err := NewServer(config, log)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest("GET", "/health", nil)
	w := httptest.NewRecorder()
	server.handleHealth(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", w.Code)
	}
}

func TestHandleGetCA_NotFound(t *testing.T) {
	log, _ := logger.NewLogger("")
	config := &ServerConfig{DBPath: ":memory:", CertDir: t.TempDir()}
	server, err := NewServer(config, log)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest("GET", "/ca/root", nil)
	w := httptest.NewRecorder()
	server.handleGetCA(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("Expected 404, got %d", w.Code)
	}
}

func TestHandleGetCRL_NotFound(t *testing.T) {
	log, _ := logger.NewLogger("")
	config := &ServerConfig{DBPath: ":memory:", CertDir: t.TempDir()}
	server, err := NewServer(config, log)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest("GET", "/crl?ca=intermediate", nil)
	w := httptest.NewRecorder()
	server.handleGetCRL(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("Expected 404, got %d", w.Code)
	}
}
