use anyhow::Result;
use clap::Parser;

use newppp::config::Command;

fn main() -> Result<()> {
    // Config file support: pull `--config` out of raw argv (the file's args
    // are prepended to the real argv, so CLI flags win). Explicit `--config`
    // must point at an existing file; `./newppp.conf` is optional.
    let (config_path, argv_rest) = newppp::config::extract_config_arg(std::env::args().collect())?;
    let mut file_args = newppp::config::file_args(config_path.as_deref())?;
    newppp::config::strip_cli_overridden(&mut file_args, &argv_rest[1..]);

    // Config-file args go first; argv[0] must lead for clap's parser to see
    // real flags as flags, then the rest of the raw argv (its [0] is skipped,
    // it only named the executable).
    let cli = newppp::config::Cli::try_parse_from(
        std::iter::once("newppp".to_string())
            .chain(file_args)
            .chain(argv_rest.into_iter().skip(1)),
    )
    .unwrap_or_else(|e| e.exit());

    // The healthcheck subcommand is a one-shot probe for docker HEALTHCHECK:
    // exit 0 healthy / 1 unhealthy, no mode/auth flags required.
    if let Some(Command::Healthcheck { url }) = &cli.command {
        std::process::exit(newppp::health::healthcheck(url));
    }

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
        newppp::clock::spawn(&cli.time);
        if cli.server {
            let cfg = cli.server_config()?;
            newppp::server::run(cfg).await
        } else {
            let cfg = cli.client_config()?;
            newppp::client::run(cfg).await
        }
    })
}
