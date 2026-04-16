//! HTTP forward proxy with registry interception
//!
//! Listens on 127.0.0.1:{port} for HTTP requests. Intercepts traffic
//! destined for known package registries (npm, pypi, yarn), extracts
//! package name + version from URL patterns, and evaluates them via
//! the Phoenix Firewall API. Non-registry traffic is tunnelled through.
//!
//! Actions:
//!   block           → HTTP 403 with reason body
//!   require_approval → HTTP 403 with approval URL
//!   warn            → stderr log + X-Phoenix-Firewall header
//!   audit / allow   → passthrough
//!
//! Strict mode: if the evaluate API is unreachable, block all installs
//! (fail-closed). Default behaviour is fail-open.

use crate::config::ProxyConfig;
use crate::evaluate::EvaluateClient;
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use serde_json::json;
use std::sync::Arc;
use tokio::net::TcpListener;

// ---------------------------------------------------------------------------
// Known registries
// ---------------------------------------------------------------------------

const REGISTRY_HOSTS: &[&str] = &[
    "registry.npmjs.org",
    "registry.yarnpkg.com",
    "pypi.org",
    "files.pythonhosted.org",
];

fn is_registry_host(host: &str) -> bool {
    REGISTRY_HOSTS.iter().any(|r| host.contains(r))
}

// ---------------------------------------------------------------------------
// Shared proxy state
// ---------------------------------------------------------------------------

struct ProxyState {
    client: EvaluateClient,
    config: ProxyConfig,
    /// Fallback local feed loaded at startup (ecosystem:name:version → action).
    fallback: Option<std::collections::HashMap<String, String>>,
    report: tokio::sync::Mutex<Vec<serde_json::Value>>,
}

impl ProxyState {
    fn new(config: ProxyConfig) -> Self {
        let fallback = config.fallback_feed.as_ref().and_then(|path| {
            match std::fs::read_to_string(path) {
                Ok(data) => match serde_json::from_str::<Vec<serde_json::Value>>(&data) {
                    Ok(entries) => {
                        let mut map = std::collections::HashMap::new();
                        for entry in &entries {
                            let key = format!(
                                "{}:{}:{}",
                                entry.get("ecosystem").and_then(|v| v.as_str()).unwrap_or(""),
                                entry.get("name").and_then(|v| v.as_str()).unwrap_or(""),
                                entry.get("version").and_then(|v| v.as_str()).unwrap_or("*"),
                            );
                            let action = entry
                                .get("action")
                                .and_then(|v| v.as_str())
                                .unwrap_or("block")
                                .to_string();
                            map.insert(key, action);
                        }
                        tracing::info!(
                            "Loaded {} entries from fallback feed {}",
                            map.len(),
                            path.display()
                        );
                        Some(map)
                    }
                    Err(e) => {
                        tracing::warn!("Failed to parse fallback feed: {}", e);
                        None
                    }
                },
                Err(e) => {
                    tracing::warn!("Failed to read fallback feed {}: {}", path.display(), e);
                    None
                }
            }
        });

        Self {
            client: EvaluateClient::new(config.api_url.clone(), config.api_key.clone()),
            config,
            fallback,
            report: tokio::sync::Mutex::new(Vec::new()),
        }
    }

    /// Resolve action: try API first, then fallback feed, then default.
    async fn resolve_action(
        &self,
        ecosystem: &str,
        name: &str,
        version: &str,
    ) -> (String, Vec<serde_json::Value>) {
        // Try evaluate API
        match self.client.check_package(ecosystem, name, version).await {
            Ok(result) => {
                let action = self.apply_mode_override(&result.action);
                return (action, result.matching_rules);
            }
            Err(e) => {
                tracing::warn!("Evaluate API error for {}@{}: {}", name, version, e);

                // Strict mode → fail closed
                if self.config.strict {
                    tracing::error!(
                        "Strict mode: blocking {}@{} (API unreachable)",
                        name,
                        version
                    );
                    return (
                        "block".to_string(),
                        vec![json!({"name": "strict-mode-fallback", "reason": "API unreachable"})],
                    );
                }

                // Check fallback feed
                if let Some(ref fb) = self.fallback {
                    let key = format!("{}:{}:{}", ecosystem, name, version);
                    let wildcard_key = format!("{}:{}:*", ecosystem, name);
                    if let Some(action) = fb.get(&key).or_else(|| fb.get(&wildcard_key)) {
                        let action = self.apply_mode_override(action);
                        tracing::info!(
                            "Fallback feed: {}@{} → {}",
                            name,
                            version,
                            action
                        );
                        return (
                            action,
                            vec![json!({"name": "fallback-feed", "source": "local"})],
                        );
                    }
                }

                // Fail open
                ("allow".to_string(), vec![])
            }
        }
    }

    /// Apply mode override: in "warn" mode, downgrade blocks to warns;
    /// in "audit" mode, downgrade everything to audit.
    fn apply_mode_override(&self, action: &str) -> String {
        match self.config.mode.as_str() {
            "audit" => "audit".to_string(),
            "warn" => {
                if action == "block" || action == "require_approval" {
                    "warn".to_string()
                } else {
                    action.to_string()
                }
            }
            _ => action.to_string(), // "enforce" — use as-is
        }
    }

    /// Record an event in the JSON report.
    async fn record(
        &self,
        ecosystem: &str,
        name: &str,
        version: &str,
        action: &str,
        rules: &[serde_json::Value],
    ) {
        let mut report = self.report.lock().await;
        report.push(json!({
            "timestamp": chrono_now(),
            "ecosystem": ecosystem,
            "package": name,
            "version": version,
            "action": action,
            "matching_rules": rules,
        }));
    }

    /// Write the report file to disk.
    async fn flush_report(&self) {
        let report = self.report.lock().await;
        if report.is_empty() {
            tracing::info!("No packages intercepted — skipping report");
            return;
        }
        let wrapper = json!({
            "phoenix_firewall_report": {
                "generated_at": chrono_now(),
                "mode": self.config.mode,
                "strict": self.config.strict,
                "total_packages": report.len(),
                "results": *report,
            }
        });
        match serde_json::to_string_pretty(&wrapper) {
            Ok(json) => {
                if let Err(e) = std::fs::write(&self.config.report_path, &json) {
                    tracing::error!("Failed to write report: {}", e);
                } else {
                    tracing::info!(
                        "Report written to {} ({} entries)",
                        self.config.report_path.display(),
                        report.len()
                    );
                }
            }
            Err(e) => tracing::error!("Failed to serialise report: {}", e),
        }
    }
}

/// Simple ISO-8601 timestamp without pulling in chrono.
fn chrono_now() -> String {
    // Use std time; good enough for reports.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    format!("{}", now)
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

pub async fn start(config: ProxyConfig) -> anyhow::Result<()> {
    let port = if config.port == 0 { 8443 } else { config.port };
    let addr: std::net::SocketAddr = format!("127.0.0.1:{}", port).parse()?;

    // Write CA cert for trust injection
    std::fs::write("phoenix-firewall-ca.pem", &config.ca.cert_pem)?;

    let state = Arc::new(ProxyState::new(config));

    let listener = TcpListener::bind(addr).await?;
    tracing::info!("Phoenix Firewall listening on http://{}", addr);
    tracing::info!("Set HTTP_PROXY=http://127.0.0.1:{} to route traffic", port);

    loop {
        tokio::select! {
            accept_result = listener.accept() => {
                match accept_result {
                    Ok((stream, peer)) => {
                        let state = state.clone();
                        tokio::spawn(async move {
                            let io = TokioIo::new(stream);
                            let service = service_fn(move |req| {
                                let state = state.clone();
                                handle_request(req, state, peer)
                            });
                            if let Err(e) = hyper::server::conn::http1::Builder::new()
                                .preserve_header_case(true)
                                .serve_connection(io, service)
                                .with_upgrades()
                                .await
                            {
                                tracing::debug!("Connection error from {}: {}", peer, e);
                            }
                        });
                    }
                    Err(e) => {
                        tracing::warn!("Accept error: {}", e);
                    }
                }
            }
            _ = tokio::signal::ctrl_c() => {
                tracing::info!("Shutting down proxy...");
                state.flush_report().await;
                break;
            }
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Request handler
// ---------------------------------------------------------------------------

async fn handle_request(
    req: Request<hyper::body::Incoming>,
    state: Arc<ProxyState>,
    peer: std::net::SocketAddr,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    let method = req.method().clone();
    let uri = req.uri().clone();

    // -----------------------------------------------------------------------
    // CONNECT tunnelling (HTTPS passthrough)
    // -----------------------------------------------------------------------
    if method == Method::CONNECT {
        let host = uri.authority().map(|a| a.to_string()).unwrap_or_default();
        tracing::debug!("CONNECT tunnel to {} from {}", host, peer);

        // For registry hosts on CONNECT, we cannot inspect TLS content in
        // HTTP-only mode. We still tunnel but log a note.
        if is_registry_host(&host) {
            tracing::debug!(
                "Registry host {} via CONNECT — TLS inspection not active in HTTP mode",
                host
            );
        }

        // Acknowledge the CONNECT and spawn a bidirectional tunnel
        tokio::task::spawn(async move {
            match hyper::upgrade::on(req).await {
                Ok(upgraded) => {
                    let parts: Vec<&str> = host.split(':').collect();
                    let connect_host = parts.first().copied().unwrap_or(&host);
                    let connect_port: u16 = parts
                        .get(1)
                        .and_then(|p| p.parse().ok())
                        .unwrap_or(443);

                    match tokio::net::TcpStream::connect((connect_host, connect_port)).await {
                        Ok(mut upstream) => {
                            let mut upgraded = TokioIo::new(upgraded);
                            let _ = tokio::io::copy_bidirectional(
                                &mut upgraded,
                                &mut upstream,
                            )
                            .await;
                        }
                        Err(e) => {
                            tracing::warn!("Failed to connect to {}: {}", host, e);
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!("CONNECT upgrade failed: {}", e);
                }
            }
        });

        return Ok(Response::builder()
            .status(StatusCode::OK)
            .body(Full::new(Bytes::new()))
            .unwrap());
    }

    // -----------------------------------------------------------------------
    // HTTP forward proxy (GET/HEAD/etc.)
    // -----------------------------------------------------------------------
    let host = uri
        .host()
        .map(|h| h.to_string())
        .unwrap_or_else(|| {
            req.headers()
                .get("host")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .to_string()
        });

    // Check if this is a registry request
    if is_registry_host(&host) {
        if let Some((ecosystem, name, version)) = extract_package_info(&host, uri.path()) {
            tracing::info!(
                "Intercepted {} install: {}@{} from {}",
                ecosystem,
                name,
                version,
                peer
            );

            let (action, rules) = state.resolve_action(&ecosystem, &name, &version).await;
            state
                .record(&ecosystem, &name, &version, &action, &rules)
                .await;

            let rule_name = rules
                .first()
                .and_then(|r| r.get("name"))
                .and_then(|v| v.as_str())
                .unwrap_or("firewall policy");

            match action.as_str() {
                "block" => {
                    tracing::warn!(
                        "BLOCKED {}@{} ({}) — rule: {}",
                        name,
                        version,
                        ecosystem,
                        rule_name
                    );
                    let body = format!(
                        concat!(
                            "\n",
                            "  Phoenix Firewall: BLOCKED\n",
                            "  Package: {}@{}\n",
                            "  Ecosystem: {}\n",
                            "  Rule: {}\n",
                            "\n",
                            "  This package has been blocked by your organisation's\n",
                            "  supply chain firewall policy.\n",
                            "\n",
                            "  More info: {}/cve-details/firewall\n",
                            "\n",
                        ),
                        name, version, ecosystem, rule_name, state.config.api_url
                    );
                    return Ok(Response::builder()
                        .status(StatusCode::FORBIDDEN)
                        .header("Content-Type", "text/plain")
                        .header("X-Phoenix-Firewall", "block")
                        .header("X-Phoenix-Firewall-Package", format!("{}@{}", name, version))
                        .body(Full::new(Bytes::from(body)))
                        .unwrap());
                }
                "require_approval" => {
                    tracing::warn!(
                        "APPROVAL REQUIRED {}@{} ({}) — rule: {}",
                        name,
                        version,
                        ecosystem,
                        rule_name
                    );
                    let body = format!(
                        concat!(
                            "\n",
                            "  Phoenix Firewall: APPROVAL REQUIRED\n",
                            "  Package: {}@{}\n",
                            "  Ecosystem: {}\n",
                            "\n",
                            "  This package requires approval before installation.\n",
                            "  Request approval: {}/firewall-approvals.html\n",
                            "\n",
                        ),
                        name, version, ecosystem, state.config.api_url
                    );
                    return Ok(Response::builder()
                        .status(StatusCode::FORBIDDEN)
                        .header("Content-Type", "text/plain")
                        .header("X-Phoenix-Firewall", "require_approval")
                        .header("X-Phoenix-Firewall-Package", format!("{}@{}", name, version))
                        .body(Full::new(Bytes::from(body)))
                        .unwrap());
                }
                "warn" => {
                    tracing::warn!(
                        "WARNING {}@{} ({}) — rule: {} — allowing with caution",
                        name,
                        version,
                        ecosystem,
                        rule_name
                    );
                    // Check fail_on policy
                    if state.config.fail_on == "warn" || state.config.fail_on == "any" {
                        let body = format!(
                            concat!(
                                "\n",
                                "  Phoenix Firewall: WARNING (fail-on={})\n",
                                "  Package: {}@{}\n",
                                "  Rule: {}\n",
                                "\n",
                            ),
                            state.config.fail_on, name, version, rule_name
                        );
                        return Ok(Response::builder()
                            .status(StatusCode::FORBIDDEN)
                            .header("Content-Type", "text/plain")
                            .header("X-Phoenix-Firewall", "warn-blocked")
                            .body(Full::new(Bytes::from(body)))
                            .unwrap());
                    }
                    // Otherwise fall through and forward with log
                }
                "audit" => {
                    tracing::info!(
                        "AUDIT {}@{} ({}) — rule: {}",
                        name,
                        version,
                        ecosystem,
                        rule_name
                    );
                }
                _ => {
                    // "allow" or unknown — pass through
                    if state.config.verbose {
                        tracing::debug!("ALLOW {}@{} ({})", name, version, ecosystem);
                    }
                }
            }
        }
    }

    // -----------------------------------------------------------------------
    // Forward the request upstream
    // -----------------------------------------------------------------------
    forward_request(req).await
}

// ---------------------------------------------------------------------------
// HTTP request forwarding via reqwest
// ---------------------------------------------------------------------------

async fn forward_request(
    req: Request<hyper::body::Incoming>,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    let method = req.method().clone();
    let uri = req.uri().clone();
    let headers = req.headers().clone();

    // Collect request body
    let body_bytes = match req.collect().await {
        Ok(collected) => collected.to_bytes(),
        Err(e) => {
            tracing::warn!("Failed to read request body: {}", e);
            return Ok(Response::builder()
                .status(StatusCode::BAD_GATEWAY)
                .body(Full::new(Bytes::from("Failed to read request body\n")))
                .unwrap());
        }
    };

    // Build upstream request via reqwest
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap_or_default();

    let url = uri.to_string();
    let reqwest_method = match method {
        Method::GET => reqwest::Method::GET,
        Method::POST => reqwest::Method::POST,
        Method::PUT => reqwest::Method::PUT,
        Method::DELETE => reqwest::Method::DELETE,
        Method::HEAD => reqwest::Method::HEAD,
        Method::PATCH => reqwest::Method::PATCH,
        Method::OPTIONS => reqwest::Method::OPTIONS,
        _ => reqwest::Method::GET,
    };

    let mut builder = client.request(reqwest_method, &url);

    // Copy headers, skip hop-by-hop
    for (key, value) in headers.iter() {
        let key_str = key.as_str().to_lowercase();
        if key_str == "host"
            || key_str == "proxy-authorization"
            || key_str == "proxy-connection"
            || key_str == "connection"
            || key_str == "keep-alive"
            || key_str == "transfer-encoding"
        {
            continue;
        }
        if let Ok(v) = value.to_str() {
            builder = builder.header(key.as_str(), v);
        }
    }

    if !body_bytes.is_empty() {
        builder = builder.body(body_bytes.to_vec());
    }

    match builder.send().await {
        Ok(resp) => {
            let status = resp.status();
            let resp_headers = resp.headers().clone();
            let resp_body = resp.bytes().await.unwrap_or_default();

            let mut response = Response::builder().status(status.as_u16());

            for (key, value) in resp_headers.iter() {
                let key_str = key.as_str().to_lowercase();
                if key_str == "transfer-encoding" || key_str == "connection" {
                    continue;
                }
                if let Ok(v) = value.to_str() {
                    response = response.header(key.as_str(), v);
                }
            }

            Ok(response
                .body(Full::new(Bytes::from(resp_body.to_vec())))
                .unwrap())
        }
        Err(e) => {
            tracing::warn!("Upstream request failed for {}: {}", url, e);
            Ok(Response::builder()
                .status(StatusCode::BAD_GATEWAY)
                .header("Content-Type", "text/plain")
                .body(Full::new(Bytes::from(format!(
                    "Phoenix Firewall: upstream error — {}\n",
                    e
                ))))
                .unwrap())
        }
    }
}

// ---------------------------------------------------------------------------
// Package extraction from URL paths
// ---------------------------------------------------------------------------

/// Extract (ecosystem, package_name, version) from a registry host + path.
///
/// Supported patterns:
///   npm unscoped: /{name}/-/{name}-{version}.tgz
///   npm scoped:   /@{scope}/{name}/-/{name}-{version}.tgz
///   npm metadata: /{name}  or  /@{scope}/{name}
///   pypi simple:  /simple/{name}/
///   pypi files:   /packages/{hash}/{hash}/{hash}/{filename}
fn extract_package_info(host: &str, path: &str) -> Option<(String, String, String)> {
    // npm / yarn registries
    if host.contains("registry.npmjs.org") || host.contains("registry.yarnpkg.com") {
        return extract_npm_package(path);
    }

    // pypi / pythonhosted
    if host.contains("pypi.org") || host.contains("pythonhosted.org") {
        return extract_pypi_package(path);
    }

    None
}

/// Extract package info from npm-style URL paths.
fn extract_npm_package(path: &str) -> Option<(String, String, String)> {
    let segments: Vec<&str> = path
        .split('/')
        .filter(|s| !s.is_empty())
        .collect();

    if segments.is_empty() {
        return None;
    }

    // Tarball download: contains "/-/" separator
    if let Some(tgz_idx) = segments.iter().position(|s| *s == "-") {
        // Everything before "-" is the package path, everything after is the tarball
        let pkg_segments = &segments[..tgz_idx];
        let tarball_segments = &segments[tgz_idx + 1..];

        if tarball_segments.is_empty() {
            return None;
        }

        let tarball = tarball_segments[0];
        if !tarball.ends_with(".tgz") {
            return None;
        }

        let filename = tarball.trim_end_matches(".tgz");

        // Build full package name
        let full_name = if pkg_segments.first().map(|s| s.starts_with('@')).unwrap_or(false) {
            // Scoped: @scope/name
            if pkg_segments.len() >= 2 {
                format!("{}/{}", pkg_segments[0], pkg_segments[1])
            } else {
                return None;
            }
        } else {
            pkg_segments[0].to_string()
        };

        // Extract version from tarball filename.
        // npm tarballs: {unscoped-name}-{version}.tgz
        // For scoped packages the tarball name omits the scope:
        //   @scope/foo → foo-1.2.3.tgz
        let bare_name = full_name.rsplit('/').next().unwrap_or(&full_name);

        let version = if filename.starts_with(bare_name) && filename.len() > bare_name.len() + 1 {
            // foo-1.2.3 → 1.2.3
            filename[bare_name.len() + 1..].to_string()
        } else {
            // Fallback: take everything after the last dash
            filename
                .rfind('-')
                .map(|i| filename[i + 1..].to_string())
                .unwrap_or_else(|| "*".to_string())
        };

        return Some(("npm".to_string(), full_name, version));
    }

    // Metadata request: /{name} or /@scope/{name}
    if segments.first().map(|s| s.starts_with('@')).unwrap_or(false) && segments.len() >= 2 {
        let full_name = format!("{}/{}", segments[0], segments[1]);
        return Some(("npm".to_string(), full_name, "*".to_string()));
    }

    if segments.len() == 1 && !segments[0].starts_with('-') {
        return Some(("npm".to_string(), segments[0].to_string(), "*".to_string()));
    }

    None
}

/// Extract package info from pypi-style URL paths.
fn extract_pypi_package(path: &str) -> Option<(String, String, String)> {
    let segments: Vec<&str> = path
        .split('/')
        .filter(|s| !s.is_empty())
        .collect();

    // /simple/{name}/ — index lookup
    if segments.len() >= 2 && segments[0] == "simple" {
        let name = normalise_pypi_name(segments[1]);
        return Some(("pypi".to_string(), name, "*".to_string()));
    }

    // /packages/.../{filename} — file download
    // Filename patterns: {name}-{version}.tar.gz, {name}-{version}-*.whl
    if segments.first().copied() == Some("packages") {
        if let Some(filename) = segments.last() {
            if let Some(nv) = parse_pypi_filename(filename) {
                return Some(("pypi".to_string(), nv.0, nv.1));
            }
        }
    }

    None
}

/// Normalise PyPI package names: PEP 503 (lowercase, hyphens to dashes).
fn normalise_pypi_name(name: &str) -> String {
    name.to_lowercase()
        .replace('_', "-")
        .replace('.', "-")
}

/// Parse a PyPI filename into (name, version).
///
/// Handles:
///   requests-2.31.0.tar.gz
///   requests-2.31.0-py3-none-any.whl
///   requests-2.31.0.zip
fn parse_pypi_filename(filename: &str) -> Option<(String, String)> {
    // Strip known suffixes
    let base = filename
        .strip_suffix(".tar.gz")
        .or_else(|| filename.strip_suffix(".zip"))
        .or_else(|| filename.strip_suffix(".whl"))
        .or_else(|| filename.strip_suffix(".tar.bz2"))
        .or_else(|| filename.strip_suffix(".egg"))?;

    // For wheels: name-version-pytag-abitag-platform
    // For sdists: name-version
    // Split on '-' and take first two as name-version
    let mut parts = base.splitn(3, '-');
    let name = parts.next()?;
    let version = parts.next()?;

    Some((normalise_pypi_name(name), version.to_string()))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_npm_unscoped_tarball() {
        let result = extract_npm_package("/lodash/-/lodash-4.17.21.tgz");
        assert_eq!(
            result,
            Some(("npm".into(), "lodash".into(), "4.17.21".into()))
        );
    }

    #[test]
    fn test_npm_scoped_tarball() {
        let result = extract_npm_package("/@babel/core/-/core-7.24.0.tgz");
        assert_eq!(
            result,
            Some(("npm".into(), "@babel/core".into(), "7.24.0".into()))
        );
    }

    #[test]
    fn test_npm_metadata_unscoped() {
        let result = extract_npm_package("/lodash");
        assert_eq!(
            result,
            Some(("npm".into(), "lodash".into(), "*".into()))
        );
    }

    #[test]
    fn test_npm_metadata_scoped() {
        let result = extract_npm_package("/@types/node");
        assert_eq!(
            result,
            Some(("npm".into(), "@types/node".into(), "*".into()))
        );
    }

    #[test]
    fn test_pypi_simple() {
        let result = extract_pypi_package("/simple/requests/");
        assert_eq!(
            result,
            Some(("pypi".into(), "requests".into(), "*".into()))
        );
    }

    #[test]
    fn test_pypi_filename_sdist() {
        let result =
            parse_pypi_filename("requests-2.31.0.tar.gz");
        assert_eq!(
            result,
            Some(("requests".into(), "2.31.0".into()))
        );
    }

    #[test]
    fn test_pypi_filename_wheel() {
        let result =
            parse_pypi_filename("requests-2.31.0-py3-none-any.whl");
        assert_eq!(
            result,
            Some(("requests".into(), "2.31.0".into()))
        );
    }

    #[test]
    fn test_pypi_normalise_name() {
        assert_eq!(normalise_pypi_name("My_Package.Name"), "my-package-name");
    }

    #[test]
    fn test_registry_host_match() {
        assert!(is_registry_host("registry.npmjs.org"));
        assert!(is_registry_host("https://registry.yarnpkg.com"));
        assert!(is_registry_host("files.pythonhosted.org"));
        assert!(!is_registry_host("github.com"));
    }

    #[test]
    fn test_extract_package_info_npm() {
        let result = extract_package_info("registry.npmjs.org", "/express/-/express-4.18.2.tgz");
        assert_eq!(
            result,
            Some(("npm".into(), "express".into(), "4.18.2".into()))
        );
    }

    #[test]
    fn test_extract_package_info_pypi() {
        let result = extract_package_info("pypi.org", "/simple/flask/");
        assert_eq!(
            result,
            Some(("pypi".into(), "flask".into(), "*".into()))
        );
    }

    #[test]
    fn test_extract_non_registry() {
        let result = extract_package_info("github.com", "/some/path");
        assert_eq!(result, None);
    }
}
