//! Phoenix Firewall Evaluate API client with LRU cache

use lru::LruCache;
use serde::{Deserialize, Serialize};
use std::num::NonZeroUsize;
use std::sync::Mutex;

#[derive(Debug, Serialize)]
pub struct EvaluateRequest {
    pub packages: Vec<PackageRef>,
}

#[derive(Debug, Serialize, Clone)]
pub struct PackageRef {
    pub ecosystem: String,
    pub name: String,
    pub version: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct EvaluateResponse {
    pub results: Vec<PackageResult>,
    pub evaluated_at: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct PackageResult {
    pub package: String,
    pub version: String,
    pub ecosystem: String,
    pub action: String,
    pub matching_rules: Vec<serde_json::Value>,
    pub mpi: Option<serde_json::Value>,
}

pub struct EvaluateClient {
    api_url: String,
    api_key: String,
    client: reqwest::Client,
    cache: Mutex<LruCache<String, PackageResult>>,
}

impl EvaluateClient {
    pub fn new(api_url: String, api_key: String) -> Self {
        Self {
            api_url,
            api_key,
            client: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(10))
                .build()
                .expect("Failed to build HTTP client"),
            cache: Mutex::new(LruCache::new(NonZeroUsize::new(10_000).unwrap())),
        }
    }

    /// Check a single package against the evaluate API (with LRU cache).
    pub async fn check_package(
        &self,
        ecosystem: &str,
        name: &str,
        version: &str,
    ) -> anyhow::Result<PackageResult> {
        let cache_key = format!("{}:{}:{}", ecosystem, name, version);

        // Check cache
        {
            let mut cache = self.cache.lock().unwrap();
            if let Some(cached) = cache.get(&cache_key) {
                return Ok(cached.clone());
            }
        }

        // Call API
        let url = format!("{}/api/v1/firewall/evaluate", self.api_url);
        let body = EvaluateRequest {
            packages: vec![PackageRef {
                ecosystem: ecosystem.to_string(),
                name: name.to_string(),
                version: version.to_string(),
            }],
        };

        let resp = self
            .client
            .post(&url)
            .header("Authorization", format!("Bearer {}", self.api_key))
            .json(&body)
            .send()
            .await?;

        let eval_resp: EvaluateResponse = resp.json().await?;

        if let Some(result) = eval_resp.results.into_iter().next() {
            // Cache result
            let mut cache = self.cache.lock().unwrap();
            cache.put(cache_key, result.clone());
            Ok(result)
        } else {
            anyhow::bail!("No result returned for {}@{}", name, version)
        }
    }
}
