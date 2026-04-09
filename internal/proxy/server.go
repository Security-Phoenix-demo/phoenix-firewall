// Package proxy implements the HTTP MITM proxy server that intercepts
// package manager registry requests and checks them against the Phoenix firewall API.
package proxy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/elazarl/goproxy"
	"github.com/nicokoenig/phoenix-firewall/internal/client"
	"github.com/nicokoenig/phoenix-firewall/internal/config"
	"github.com/nicokoenig/phoenix-firewall/internal/registry"
)

const (
	defaultCacheSize = 10000
	defaultCacheTTL  = 5 * time.Minute
)

// Server is the MITM HTTP proxy server.
type Server struct {
	cfg        *config.Config
	ca         *tls.Certificate
	handler    *RequestHandler
	proxy      *goproxy.ProxyHttpServer
	httpSrv    *http.Server
	handlerCfg func(h *RequestHandler)
}

// NewServer creates a new proxy server with the given configuration and CA certificate.
func NewServer(cfg *config.Config) *Server {
	return &Server{cfg: cfg}
}

// SetCA configures the CA certificate used for MITM TLS interception.
func (s *Server) SetCA(ca *tls.Certificate) {
	s.ca = ca
}

// handlerConfigurator is an optional function applied to the handler after creation.
type handlerConfigurator func(h *RequestHandler)

// ConfigureHandler sets a function that will be called to configure the request
// handler after it is created during Start. This allows the caller to set
// strict mode, reporter, fallback feed, etc.
func (s *Server) ConfigureHandler(fn func(h *RequestHandler)) {
	s.handlerCfg = fn
}

// Start begins listening for HTTP proxy requests on the configured port.
// It sets up goproxy with MITM support and the request handler chain.
func (s *Server) Start() error {
	return s.StartWithContext(context.Background())
}

// StartWithContext begins listening and supports graceful shutdown via context cancellation.
func (s *Server) StartWithContext(ctx context.Context) error {
	// Build goproxy instance
	gp := goproxy.NewProxyHttpServer()
	gp.Verbose = s.cfg.Verbose
	s.proxy = gp

	// Configure MITM if CA is available
	if s.ca != nil {
		if err := s.configureMITM(gp); err != nil {
			return fmt.Errorf("configure MITM: %w", err)
		}
	}

	// Set up request handler with LRU cache
	matcher := registry.NewCompositeMatchers()
	fwClient := client.New(s.cfg.APIUrl, s.cfg.APIKey)
	s.handler = NewRequestHandler(matcher, fwClient, s.cfg.Verbose)
	cache := NewResultCache(defaultCacheSize, defaultCacheTTL)
	s.handler.SetCache(cache)

	// Apply handler configuration (strict mode, reporter, fallback feed)
	if s.handlerCfg != nil {
		s.handlerCfg(s.handler)
	}

	// Register request/response handlers
	gp.OnRequest().DoFunc(s.handler.HandleRequest)
	gp.OnResponse().DoFunc(s.handler.HandleResponse)

	addr := fmt.Sprintf(":%d", s.cfg.Port)
	s.httpSrv = &http.Server{
		Addr:    addr,
		Handler: gp,
	}

	// Graceful shutdown on context cancellation
	go func() {
		<-ctx.Done()
		log.Println("Shutting down proxy server...")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = s.httpSrv.Shutdown(shutdownCtx)
	}()

	log.Printf("Phoenix Firewall proxy listening on %s", addr)
	if err := s.httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}

// configureMITM sets up the goproxy MITM TLS configuration using the CA.
func (s *Server) configureMITM(gp *goproxy.ProxyHttpServer) error {
	caCert, err := x509.ParseCertificate(s.ca.Certificate[0])
	if err != nil {
		return fmt.Errorf("parse CA certificate: %w", err)
	}

	goproxy.GoproxyCa = *s.ca
	goproxy.OkConnect = &goproxy.ConnectAction{Action: goproxy.ConnectMitm, TLSConfig: goproxy.TLSConfigFromCA(s.ca)}
	goproxy.MitmConnect = &goproxy.ConnectAction{Action: goproxy.ConnectMitm, TLSConfig: goproxy.TLSConfigFromCA(s.ca)}
	goproxy.RejectConnect = &goproxy.ConnectAction{Action: goproxy.ConnectReject, TLSConfig: goproxy.TLSConfigFromCA(s.ca)}

	// MITM all HTTPS CONNECT requests
	gp.OnRequest().HandleConnect(goproxy.AlwaysMitm)

	log.Printf("MITM enabled with CA: %s", caCert.Subject.CommonName)
	return nil
}
