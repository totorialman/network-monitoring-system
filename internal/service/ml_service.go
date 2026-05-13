package service

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"network-monitor-backend/internal/domain"
	"sync"
	"time"
)

type MLClient interface {
	Analyze(context.Context, domain.AnalyzeRequest) (*domain.AnalyzeResponse, error)
	HealthCheck(context.Context) error
}
type mlHTTPClient struct {
	baseURL    string
	httpClient *http.Client
	cb         *CircuitBreaker
}

func NewMLClient(baseURL string, timeout time.Duration) MLClient {
	return &mlHTTPClient{baseURL: baseURL, httpClient: &http.Client{Timeout: timeout}, cb: NewCircuitBreaker(3, 30*time.Second)}
}
func (c *mlHTTPClient) Analyze(ctx context.Context, req domain.AnalyzeRequest) (*domain.AnalyzeResponse, error) {
	var result *domain.AnalyzeResponse
	err := c.cb.Call(func() error {
		body, _ := json.Marshal(req)
		httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/analyze", bytes.NewReader(body))
		if err != nil {
			return err
		}
		httpReq.Header.Set("Content-Type", "application/json")
		resp, err := c.httpClient.Do(httpReq)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		if resp.StatusCode >= 500 {
			return fmt.Errorf("ml 5xx: %d", resp.StatusCode)
		}
		if resp.StatusCode >= 300 {
			return fmt.Errorf("ml error: %d", resp.StatusCode)
		}
		var out domain.AnalyzeResponse
		if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
			return err
		}
		result = &out
		return nil
	})
	return result, err
}
func (c *mlHTTPClient) HealthCheck(ctx context.Context) error {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/health", nil)
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("ml unhealthy: %d", resp.StatusCode)
	}
	return nil
}

type CBState string

const (
	Closed   CBState = "closed"
	Open     CBState = "open"
	HalfOpen CBState = "half-open"
)

type CircuitBreaker struct {
	mu          sync.RWMutex
	failures    int
	lastFailure time.Time
	state       CBState
	threshold   int
	timeout     time.Duration
}

func NewCircuitBreaker(threshold int, timeout time.Duration) *CircuitBreaker {
	return &CircuitBreaker{threshold: threshold, timeout: timeout, state: Closed}
}
func (cb *CircuitBreaker) Call(fn func() error) error {
	cb.mu.Lock()
	if cb.state == Open && time.Since(cb.lastFailure) > cb.timeout {
		cb.state = HalfOpen
	}
	if cb.state == Open {
		cb.mu.Unlock()
		return fmt.Errorf("circuit breaker is open")
	}
	cb.mu.Unlock()
	err := fn()
	cb.mu.Lock()
	defer cb.mu.Unlock()
	if err != nil {
		cb.failures++
		cb.lastFailure = time.Now()
		if cb.failures >= cb.threshold {
			cb.state = Open
		}
		return err
	}
	cb.failures = 0
	cb.state = Closed
	return nil
}
