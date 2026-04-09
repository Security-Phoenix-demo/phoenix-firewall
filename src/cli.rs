//! Command-line interface definition

use clap::Parser;
use std::path::PathBuf;

/// Phoenix Supply Chain Firewall — package manager security proxy
#[derive(Parser, Debug)]
#[command(name = "phoenix-firewall", version, about)]
pub struct Cli {
    /// Phoenix API URL
    #[arg(long, env = "PHOENIX_API_URL", default_value = "https://api.cvedetails.io")]
    pub api_url: String,

    /// Phoenix API key
    #[arg(long, env = "PHOENIX_API_KEY")]
    pub api_key: String,

    /// CI mode: install PATH shims for transparent interception
    #[arg(long, default_value_t = false)]
    pub ci: bool,

    /// Strict mode: fail-closed when API is unreachable (default: fail-open)
    #[arg(long, default_value_t = false)]
    pub strict: bool,

    /// Local JSON feed file for offline/cached operation
    #[arg(long)]
    pub fallback_feed: Option<PathBuf>,

    /// JSON report output path
    #[arg(long, default_value = "phoenix-firewall-report.json")]
    pub report_path: PathBuf,

    /// Proxy listen port (0 = random)
    #[arg(long, default_value_t = 0)]
    pub port: u16,

    /// Override action: enforce | warn | audit
    #[arg(long, default_value = "enforce")]
    pub mode: String,

    /// Fail on: block | warn | any
    #[arg(long, default_value = "block")]
    pub fail_on: String,

    /// Minimum package age in hours (quarantine)
    #[arg(long, default_value_t = 0)]
    pub min_package_age_hours: u32,

    /// Verbose output
    #[arg(short, long, default_value_t = false)]
    pub verbose: bool,
}
