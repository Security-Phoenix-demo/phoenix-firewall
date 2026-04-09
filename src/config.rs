//! Proxy configuration

use crate::ca::EphemeralCA;
use crate::cli::Cli;
use std::path::PathBuf;

pub struct ProxyConfig {
    pub api_url: String,
    pub api_key: String,
    pub ca: EphemeralCA,
    pub port: u16,
    pub strict: bool,
    pub fallback_feed: Option<PathBuf>,
    pub report_path: PathBuf,
    pub mode: String,
    pub fail_on: String,
    pub min_package_age_hours: u32,
    pub verbose: bool,
}

impl ProxyConfig {
    pub fn from_cli(cli: &Cli, ca: EphemeralCA) -> Self {
        Self {
            api_url: cli.api_url.clone(),
            api_key: cli.api_key.clone(),
            ca,
            port: cli.port,
            strict: cli.strict,
            fallback_feed: cli.fallback_feed.clone(),
            report_path: cli.report_path.clone(),
            mode: cli.mode.clone(),
            fail_on: cli.fail_on.clone(),
            min_package_age_hours: cli.min_package_age_hours,
            verbose: cli.verbose,
        }
    }
}
