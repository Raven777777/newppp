use anyhow::Result;
use clap::Parser;

use newppp::config::Cli;

fn main() -> Result<()> {
    let cli = Cli::parse();
    cli.validate()?;

    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(cli.log.clone()));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .init();

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;

    runtime.block_on(async move {
        let _ = rustls::crypto::ring::default_provider().install_default();
        if cli.server {
            let cfg = cli.server_config()?;
            newppp::server::run(cfg).await
        } else {
            let cfg = cli.client_config()?;
            newppp::client::run(cfg).await
        }
    })
}
