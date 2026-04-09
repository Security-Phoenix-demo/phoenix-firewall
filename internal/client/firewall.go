// Package client provides an HTTP client for the Phoenix Security firewall API.
package client

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// CheckResult holds the response from the firewall evaluate endpoint.
type CheckResult struct {
	// Allowed is true if the package is safe to install.
	Allowed bool `json:"allowed"`
	// Verdict is a short string label (e.g. "safe", "malicious", "unknown").
	Verdict string `json:"verdict"`
	// Reason provides a human-readable explanation for the verdict.
	Reason string `json:"reason"`
	// Score is the risk score returned by the API (0-100).
	Score float64 `json:"score"`
	// Action is the recommended action (allow, warn, block).
	Action string `json:"action"`
	// Confidence is the confidence level of the verdict (0-1).
	Confidence float64 `json:"confidence"`
}

// Client communicates with the Phoenix firewall API.
type Client struct {
	baseURL    string
	apiKey     string
	httpClient *http.Client
}

// New creates a new firewall API client.
func New(baseURL, apiKey string) *Client {
	return &Client{
		baseURL: baseURL,
		apiKey:  apiKey,
		httpClient: &http.Client{
			Timeout: 5 * time.Second,
		},
	}
}

// evaluateRequest is the JSON body sent to the firewall evaluate endpoint.
type evaluateRequest struct {
	Packages []packageEntry `json:"packages"`
}

type packageEntry struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
	Version   string `json:"version"`
}

// evaluateResponse is the JSON response from the firewall evaluate endpoint.
type evaluateResponse struct {
	Results []evaluateResult `json:"results"`
}

type mpiData struct {
	Signals         []string `json:"signals"`
	Confidence      float64  `json:"confidence"`
	ThreatType      string   `json:"threat_type,omitempty"`
	MitreTechniques []string `json:"mitre_techniques"`
}

type evaluateResult struct {
	Package    string  `json:"package"`
	Version    string  `json:"version"`
	Ecosystem  string  `json:"ecosystem"`
	Action     string  `json:"action"`
	MPI        mpiData `json:"mpi"`
	PsOssScore *int    `json:"ps_oss_score,omitempty"`
}

// Check evaluates a package against the Phoenix firewall API.
func (c *Client) Check(ecosystem, name, version string) (*CheckResult, error) {
	reqBody := evaluateRequest{
		Packages: []packageEntry{
			{
				Ecosystem: ecosystem,
				Name:      name,
				Version:   version,
			},
		},
	}

	jsonBody, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}

	url := fmt.Sprintf("%s/api/v1/firewall/evaluate", c.baseURL)
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(jsonBody))
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if c.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.apiKey)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("firewall API request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("firewall API returned %d: %s", resp.StatusCode, string(body))
	}

	var evalResp evaluateResponse
	if err := json.Unmarshal(body, &evalResp); err != nil {
		return nil, fmt.Errorf("unmarshal response: %w", err)
	}

	if len(evalResp.Results) == 0 {
		// No results — treat as allowed/unknown
		return &CheckResult{
			Allowed: true,
			Verdict: "unknown",
			Reason:  "no results from firewall API",
		}, nil
	}

	r := evalResp.Results[0]
	allowed := r.Action != "block"
	verdict := "safe"
	if r.Action == "block" {
		verdict = "malicious"
	} else if r.Action == "warn" {
		verdict = "suspicious"
	}

	reason := fmt.Sprintf("action=%s", r.Action)
	if r.MPI.ThreatType != "" {
		reason = fmt.Sprintf("%s, threat_type=%s", reason, r.MPI.ThreatType)
	}
	if len(r.MPI.Signals) > 0 {
		reason = fmt.Sprintf("%s, signals=%v", reason, r.MPI.Signals)
	}

	score := float64(0)
	if r.PsOssScore != nil {
		score = float64(*r.PsOssScore)
	}

	return &CheckResult{
		Allowed:    allowed,
		Verdict:    verdict,
		Reason:     reason,
		Score:      score,
		Action:     r.Action,
		Confidence: r.MPI.Confidence,
	}, nil
}
