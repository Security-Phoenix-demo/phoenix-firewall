package proxy_test

import "github.com/nicokoenig/phoenix-firewall/internal/client"

// newTestClient creates a firewall client pointing at a test server URL.
func newTestClient(baseURL, apiKey string) *client.Client {
	return client.New(baseURL, apiKey)
}
