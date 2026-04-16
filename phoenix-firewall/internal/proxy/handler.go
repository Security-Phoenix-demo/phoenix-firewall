package proxy

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	"github.com/elazarl/goproxy"
	"github.com/nicokoenig/phoenix-firewall/internal/client"
	"github.com/nicokoenig/phoenix-firewall/internal/registry"
)

// BlockResponse is the JSON body returned when a package is blocked.
type BlockResponse struct {
	Blocked bool   `json:"blocked"`
	Reason  string `json:"reason"`
	Package string `json:"package"`
	Action  string `json:"action"`
}

// RequestHandler intercepts proxy requests and checks packages against the firewall API.
type RequestHandler struct {
	matcher      registry.RegistryMatcher
	client       *client.Client
	cache        *ResultCache
	verbose      bool
	strictMode   bool
	reporter     *Reporter
	fallbackFeed *FallbackFeed
}

// NewRequestHandler creates a handler with the given matcher and firewall client.
func NewRequestHandler(matcher registry.RegistryMatcher, fwClient *client.Client, verbose bool) *RequestHandler {
	return &RequestHandler{
		matcher: matcher,
		client:  fwClient,
		verbose: verbose,
	}
}

// SetCache attaches a result cache to the handler.
func (h *RequestHandler) SetCache(cache *ResultCache) {
	h.cache = cache
}

// SetReporter attaches a reporter for recording check results.
func (h *RequestHandler) SetReporter(r *Reporter) {
	h.reporter = r
}

// SetStrictMode enables strict mode where "warn" actions are treated as "block".
func (h *RequestHandler) SetStrictMode(strict bool) {
	h.strictMode = strict
}

// SetFallbackFeed sets a local fallback feed for offline checking.
func (h *RequestHandler) SetFallbackFeed(feed *FallbackFeed) {
	h.fallbackFeed = feed
}

// HandleRequest inspects an HTTP request. If it matches a registry URL, the package
// is checked against the firewall API. Blocked packages receive a 403 response.
func (h *RequestHandler) HandleRequest(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
	urlStr := req.URL.String()
	// For HTTPS requests proxied via CONNECT, the URL may be relative.
	// Reconstruct full URL if needed.
	if req.URL.Scheme == "" && req.URL.Host == "" && req.Host != "" {
		urlStr = "https://" + req.Host + req.URL.RequestURI()
	}

	ref, err := h.matcher.Match(urlStr)
	if err != nil {
		if h.verbose {
			log.Printf("[handler] matcher error for %s: %v", urlStr, err)
		}
		return req, nil
	}
	if ref == nil {
		// Not a registry URL — pass through
		return req, nil
	}

	if h.verbose {
		log.Printf("[handler] detected %s package: %s@%s", ref.Ecosystem, ref.Name, ref.Version)
	}

	// Check cache first
	cacheKey := CacheKey(ref.Ecosystem, ref.Name, ref.Version)
	if h.cache != nil {
		if cached, ok := h.cache.Get(cacheKey); ok {
			if h.verbose {
				log.Printf("[handler] cache hit for %s", cacheKey)
			}
			result := cached
			effective := h.applyStrictMode(result)
			h.recordResult(ref, effective)
			if !effective.Allowed {
				pkgLabel := fmt.Sprintf("%s/%s@%s", ref.Ecosystem, ref.Name, ref.Version)
				reason := effective.Reason
				if reason == "" {
					reason = fmt.Sprintf("Package %s is %s", pkgLabel, effective.Verdict)
				}
				log.Printf("[BLOCKED] %s — %s (cached)", pkgLabel, reason)
				return req, blockResponse(req, pkgLabel, reason)
			}
			return req, nil
		}
	}

	// Try fallback feed if configured
	var result *client.CheckResult
	if h.fallbackFeed != nil {
		if fbResult, found := h.fallbackFeed.Check(ref.Ecosystem, ref.Name, ref.Version); found {
			result = fbResult
			if h.verbose {
				log.Printf("[handler] fallback feed hit for %s/%s@%s", ref.Ecosystem, ref.Name, ref.Version)
			}
		}
	}

	// Check against firewall API if no fallback result
	if result == nil {
		var apiErr error
		result, apiErr = h.client.Check(ref.Ecosystem, ref.Name, ref.Version)
		if apiErr != nil {
			log.Printf("[handler] firewall API error for %s/%s@%s: %v", ref.Ecosystem, ref.Name, ref.Version, apiErr)
			// Fail open by default — allow the request
			return req, nil
		}
	}

	// Apply strict mode
	result = h.applyStrictMode(result)

	// Record result for reporting
	h.recordResult(ref, result)

	// Store in cache
	if h.cache != nil {
		h.cache.Set(cacheKey, result)
	}

	if !result.Allowed {
		pkgLabel := fmt.Sprintf("%s/%s@%s", ref.Ecosystem, ref.Name, ref.Version)
		reason := result.Reason
		if reason == "" {
			reason = fmt.Sprintf("Package %s is %s", pkgLabel, result.Verdict)
		}
		log.Printf("[BLOCKED] %s — %s", pkgLabel, reason)

		return req, blockResponse(req, pkgLabel, reason)
	}

	if h.verbose {
		log.Printf("[handler] allowed %s/%s@%s (verdict=%s)", ref.Ecosystem, ref.Name, ref.Version, result.Verdict)
	}

	return req, nil
}

// HandleResponse passes responses through unchanged.
func (h *RequestHandler) HandleResponse(resp *http.Response, ctx *goproxy.ProxyCtx) *http.Response {
	return resp
}

// applyStrictMode returns a modified result where "warn" is treated as "block" if strict mode is on.
func (h *RequestHandler) applyStrictMode(result *client.CheckResult) *client.CheckResult {
	if !h.strictMode || result.Action != "warn" {
		return result
	}
	// Copy the result and upgrade warn → block
	upgraded := *result
	upgraded.Action = "block"
	upgraded.Allowed = false
	upgraded.Verdict = "malicious"
	upgraded.Reason = fmt.Sprintf("strict mode: %s", result.Reason)
	return &upgraded
}

// recordResult records a check result into the reporter if one is attached.
func (h *RequestHandler) recordResult(ref *registry.PackageRef, result *client.CheckResult) {
	if h.reporter != nil {
		h.reporter.Record(ref, result)
	}
}

// blockResponse constructs a 403 Forbidden response with a JSON body.
func blockResponse(req *http.Request, pkg, reason string) *http.Response {
	body := BlockResponse{
		Blocked: true,
		Reason:  reason,
		Package: pkg,
		Action:  "block",
	}
	jsonBytes, _ := json.Marshal(body)

	return goproxy.NewResponse(req, "application/json", http.StatusForbidden, string(jsonBytes))
}
