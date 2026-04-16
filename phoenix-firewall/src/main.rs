//! Phoenix Supply Chain Firewall — MITM proxy binary
//!
//! Intercepts package manager traffic (npm, pip, yarn, pnpm) and enforces
//! Phoenix firewall rules at install time.

mod ca;
mod cli;
mod config;
mod evaluate;
mod interceptor;
mod proxy;

use clap::Parser;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::from_default_env()
                .add_directive("phoenix_firewall=info".parse()?),
        )
        .init();

    let args = cli::Cli::parse();

    tracing::info!("Phoenix Firewall v{}", env!("CARGO_PKG_VERSION"));
    tracing::info!(
        "Mode: {}",
        if args.ci { "CI (PATH shims)" } else { "Proxy" }
    );
    tracing::info!("API: {}", args.api_url);

    // Generate ephemeral CA
    let ca = ca::EphemeralCA::generate()?;
    tracing::info!("Generated ephemeral CA certificate");

    if args.ci {
        // CI mode: install PATH shims
        interceptor::install_path_shims(&args)?;
        tracing::info!("PATH shims installed for: npm, pip, yarn, pnpm, uv, poetry");
    }

    // Start proxy
    let config = config::ProxyConfig::from_cli(&args, ca);
    proxy::start(config).await
}
