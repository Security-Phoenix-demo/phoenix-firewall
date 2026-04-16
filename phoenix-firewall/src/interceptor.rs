//! CI mode: PATH shim generation for transparent package manager interception

use crate::cli::Cli;
use std::fs;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

/// Install PATH shims that wrap common package managers.
///
/// Each shim sets `HTTPS_PROXY`, `HTTP_PROXY`, and CA bundle environment
/// variables, then delegates to the real binary found further down `$PATH`.
pub fn install_path_shims(cli: &Cli) -> anyhow::Result<()> {
    let shim_dir = PathBuf::from("/tmp/phoenix-firewall-shims");
    fs::create_dir_all(&shim_dir)?;

    let port = if cli.port == 0 { 8443 } else { cli.port };

    let managers = vec![
        ("npm", "npm"),
        ("npx", "npx"),
        ("yarn", "yarn"),
        ("pnpm", "pnpm"),
        ("pip", "pip"),
        ("pip3", "pip3"),
        ("uv", "uv"),
        ("poetry", "poetry"),
    ];

    for (name, original) in &managers {
        let shim_path = shim_dir.join(name);
        let shim_content = format!(
            r#"#!/bin/bash
# Phoenix Firewall shim for {original}
# Wraps {original} with firewall proxy
export HTTPS_PROXY="https://127.0.0.1:{port}"
export HTTP_PROXY="http://127.0.0.1:{port}"
export NODE_EXTRA_CA_CERTS="$(dirname "$0")/../phoenix-firewall-ca.pem"
export REQUESTS_CA_BUNDLE="$(dirname "$0")/../phoenix-firewall-ca.pem"
export SSL_CERT_FILE="$(dirname "$0")/../phoenix-firewall-ca.pem"

# Find the real binary (skip this shim in PATH)
REAL=$(which -a {original} 2>/dev/null | grep -v phoenix-firewall-shims | head -1)
if [ -z "$REAL" ]; then
    echo "Error: {original} not found in PATH (outside Phoenix Firewall shims)" >&2
    exit 1
fi

exec "$REAL" "$@"
"#,
            original = original,
            port = port,
        );

        fs::write(&shim_path, shim_content)?;
        #[cfg(unix)]
        fs::set_permissions(&shim_path, fs::Permissions::from_mode(0o755))?;
    }

    // Print PATH export instruction for the caller to eval
    if let Ok(path) = std::env::var("PATH") {
        println!("export PATH=\"{}:{}\"", shim_dir.display(), path);
    }

    tracing::info!(
        "Installed {} PATH shims in {}",
        managers.len(),
        shim_dir.display()
    );
    Ok(())
}
