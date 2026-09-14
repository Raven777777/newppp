use clap::Parser;

#[derive(Parser, Debug)]
#[command(
    name = "newppp",
    version,
    about = "Industrial WebTransport-based proxy",
    long_about = "WebTransport (QUIC/h3) proxy with HTTPS POST fallback.\nRun with -c (client) or -s (server)."
)]
pub struct Cli {
    /// Run in client mode
    #[arg(short = 'c')]
    pub client: bool,

    /// Run in server mode
    #[arg(short = 's')]
    pub server: bool,

    /// Credentials, user:password (repeatable on server)
    #[arg(long = "auth", value_name = "USER:PASS")]
    pub auth: Vec<String>,

    /// Log level (trace|debug|info|warn|error)
    #[arg(long = "log", value_name = "LEVEL", default_value = "info")]
    pub log: String,

    /// [client+server] time source URL for the internal clock (hourly sync
    /// from the HTTP Date header, UTC); e.g. https://time.ms/
    #[arg(
        long = "time",
        value_name = "URL",
        default_value = "https://www.cloudflare.com/cdn-cgi/trace"
    )]
    pub time: String,

    // ---------------- client options ----------------
    /// [client] WebTransport server URL: https://host[:port][/path]
    #[arg(long = "server", value_name = "URL")]
    pub server_url: Option<String>,

    /// [client] HTTPS POST fallback URL (mode A), e.g. https://host/api/ppp
    #[arg(long = "url", value_name = "URL")]
    pub url: Option<String>,

    /// [client] SOCKS5 inbound listen address
    #[arg(long = "bind", value_name = "ADDR", default_value = "127.0.0.1:1080")]
    pub bind: String,

    /// [client] HTTP proxy inbound listen address (optional)
    #[arg(long = "http-bind", value_name = "ADDR")]
    pub http_bind: Option<String>,

    /// [client] require local proxy authentication (SOCKS5 RFC1929 username/
    /// password and HTTP proxy Basic auth)
    #[arg(long = "inbound-auth", value_name = "USER:PASS")]
    pub inbound_auth: Option<String>,

    /// [client] number of pooled WebTransport connections (1..8)
    #[arg(long = "conns", value_name = "N", default_value_t = 2)]
    pub conns: usize,

    /// [client] skip TLS certificate verification (development only)
    #[arg(long = "skip-verify")]
    pub skip_verify: bool,

    /// [client] masquerade SNI: send this hostname in the TLS ClientHello
    /// (and query DNS for it) while connecting to the real server address.
    /// The real server must be identified via --pin. Implies a resolver
    /// override: the masquerade name resolves wherever DNS points it, so
    /// pair it with --pin and (recommended) a URL that carries the real
    /// address directly.
    #[arg(long = "sni", value_name = "DOMAIN")]
    pub sni: Option<String>,

    /// [client] pin the server certificate by SHA-256 fingerprint (64 hex
    /// chars). Replaces CA verification: the server's identity is exactly
    /// this certificate. Required with --sni; mutually exclusive with
    /// --skip-verify.
    #[arg(long = "pin", value_name = "SHA256")]
    pub pin: Option<String>,

    /// [client+server] QUIC per-stream receive window, MB (1..=64).
    /// Bigger = faster on clean high-latency links; smaller = more resilient
    /// to packet loss ("too many gaps" protection).
    #[arg(long = "recv-window", value_name = "MB", default_value_t = 2)]
    pub recv_window_mb: u64,

    // ---------------- server options ----------------
    /// [server] WebTransport (QUIC over UDP) listen address; omit to disable
    /// the WT listener entirely (pure-website mode, nothing to firewall)
    #[arg(long = "listen", value_name = "ADDR")]
    pub listen: Option<String>,

    /// [server] TLS certificate PEM file
    #[arg(long = "cert", value_name = "FILE")]
    pub cert: Option<String>,

    /// [server] TLS private key PEM file
    #[arg(long = "key", value_name = "FILE")]
    pub key: Option<String>,

    /// [server] generate an in-memory self-signed certificate (development only)
    #[arg(long = "self-signed")]
    pub self_signed: bool,

    /// [server] TLS TCP fallback (mode A POST) listen address
    #[arg(long = "fallback-listen", value_name = "ADDR")]
    pub fallback_listen: Option<String>,

    /// [server] plain-HTTP fallback listen address (development only)
    #[arg(long = "http-listen", value_name = "ADDR")]
    pub http_listen: Option<String>,

    /// [server] directory with Let's Encrypt http-01 challenge files, served
    /// at /.well-known/acme-challenge/ on the plain-HTTP listener
    #[arg(long = "acme-dir", value_name = "DIR")]
    pub acme_dir: Option<String>,

    /// [server] API path for the HTTP fallback endpoint
    #[arg(long = "path", value_name = "PATH", default_value = "/api/ppp")]
    pub path: String,

    /// [server] max concurrent sessions (global)
    #[arg(long = "max-sessions", value_name = "N", default_value_t = 200)]
    pub max_sessions: usize,

    /// [server] per-connection rate limit, Mbps (0 = unlimited)
    #[arg(long = "rate", value_name = "MBPS", default_value_t = 100)]
    pub rate_mbps: u64,

    /// [server] idle session timeout, seconds
    #[arg(long = "idle", value_name = "SECS", default_value_t = 60)]
    pub idle_secs: u64,

    /// [server] allow connections to loopback, private, link-local and other
    /// non-public addresses (disabled by default to prevent SSRF)
    #[arg(long = "allow-private-targets")]
    pub allow_private_targets: bool,

    /// [server] global cap on concurrent unauthenticated connections (accepted
    /// but no valid AUTH frame yet); per-source-IP cap is max_unauth/8 (2..=64)
    #[arg(long = "max-unauth", value_name = "N", default_value_t = 128)]
    pub max_unauth: u64,

    /// [client+server] health endpoint listen address (plain HTTP, loopback
    /// recommended): /healthz JSON snapshot for docker HEALTHCHECK / NAS
    #[arg(long = "health", value_name = "ADDR")]
    pub health: Option<String>,

    /// [client+server] load arguments from a config file (before those on the
    /// command line, so CLI flags take precedence); `newppp.conf` in the
    /// current directory is picked up automatically when present
    #[arg(long = "config", value_name = "FILE", global = true)]
    pub config: Option<String>,

    /// [server] graceful shutdown: how long to drain in-flight sessions after
    /// cancelling live connections before force-closing (seconds)
    #[arg(long = "shutdown-grace", value_name = "SECS", default_value_t = 10)]
    pub shutdown_grace: u64,

    #[command(subcommand)]
    pub command: Option<Command>,
}

#[derive(Debug, clap::Subcommand)]
pub enum Command {
    /// Exit 0 when a /healthz endpoint answers 200 with a snapshot body.
    /// Docker HEALTHCHECK needs this: scratch images ship no shell.
    Healthcheck {
        /// health endpoint URL (plain HTTP), e.g. http://127.0.0.1:9100/healthz
        #[arg(long = "url")]
        url: String,
    },
}

#[derive(Debug, Clone)]
pub struct ClientConfig {
    pub wt_url: Option<String>,
    pub fb_url: Option<String>,
    pub socks_bind: String,
    pub http_bind: Option<String>,
    pub inbound_auth: Option<(String, String)>,
    pub conns: usize,
    pub uid: String,
    pub password: String,
    pub skip_verify: bool,
    /// Masquerade SNI hostname (None = use the URL host as before).
    pub sni: Option<String>,
    /// SHA-256 certificate fingerprint (raw 32 bytes) to pin the server.
    pub pin: Option<[u8; 32]>,
    pub recv_window: u32,
    pub health: Option<String>,
}

/// Where the server loads its TLS material from.
#[derive(Debug, Clone)]
pub enum CertSource {
    Files { cert: String, key: String },
    SelfSigned,
}

#[derive(Debug, Clone)]
pub struct ServerConfig {
    pub listen: Option<String>,
    pub cert: CertSource,
    pub fallback_listen: Option<String>,
    pub http_listen: Option<String>,
    pub acme_dir: Option<String>,
    pub path: String,
    pub users: Vec<(String, String)>,
    pub max_sessions: usize,
    pub rate_mbps: u64,
    pub idle_secs: u64,
    pub allow_private_targets: bool,
    pub max_unauth: u64,
    pub recv_window: u32,
    pub shutdown_grace: u64,
    pub health: Option<String>,
}

fn parse_auth(raw: &str) -> anyhow::Result<(String, String)> {
    let (u, p) = raw
        .split_once(':')
        .ok_or_else(|| anyhow::anyhow!("--auth must be USER:PASS, got '{raw}'"))?;
    let uid = u.trim();
    anyhow::ensure!(
        !uid.is_empty()
            && uid.len() <= 32
            && uid
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-'),
        "invalid user id '{uid}': use [A-Za-z0-9_-], max 32 chars"
    );
    anyhow::ensure!(!p.is_empty(), "password must not be empty");
    Ok((uid.to_string(), p.to_string()))
}

/// Parse `--inbound-auth USER:PASS`. RFC1929 length fields are one byte, so
/// both parts must be 1..=255 bytes and valid UTF-8 (CLI args already are).
fn parse_inbound_auth(raw: &str) -> anyhow::Result<(String, String)> {
    let (u, p) = raw
        .split_once(':')
        .ok_or_else(|| anyhow::anyhow!("--inbound-auth must be USER:PASS, got '{raw}'"))?;
    anyhow::ensure!(
        !u.is_empty() && u.len() <= 255,
        "inbound username must be 1..=255 bytes"
    );
    anyhow::ensure!(
        !p.is_empty() && p.len() <= 255,
        "inbound password must be 1..=255 bytes"
    );
    Ok((u.to_string(), p.to_string()))
}

/// Warn when `--listen` carries a specific IP address. The WebTransport
/// listener uses QUIC `with_bind_default`, which always binds the wildcard
/// address, so a specific IP is silently ignored (D6: make it visible).
fn warn_listen_ip_ignored(addr: &str) {
    if let Ok(sa) = addr.parse::<std::net::SocketAddr>() {
        if !sa.ip().is_unspecified() {
            tracing::warn!(
                "--listen {addr}: IP part is ignored — WebTransport always binds all \
                 interfaces (udp 0.0.0.0/::). Restrict access with a firewall."
            );
        }
    }
}

/// Warn when an inbound proxy listener is bound to a wildcard address without
/// `--inbound-auth`: that exposes an open proxy to the whole network.
fn warn_open_inbound(label: &str, addr: &str, has_auth: bool) {
    if has_auth {
        return;
    }
    if let Ok(sa) = addr.parse::<std::net::SocketAddr>() {
        if sa.ip().is_unspecified() {
            tracing::warn!(
                "{label} {addr}: bound to all interfaces without --inbound-auth — the \
                 local proxy is reachable from the network unauthenticated. Set \
                 --inbound-auth or bind 127.0.0.1."
            );
        }
    }
}

impl Cli {
    pub fn validate(&self) -> anyhow::Result<()> {
        if self.client == self.server {
            anyhow::bail!("specify exactly one mode: -c (client) or -s (server)");
        }
        anyhow::ensure!(!self.auth.is_empty(), "--auth USER:PASS is required");
        Ok(())
    }

    pub fn client_config(&self) -> anyhow::Result<ClientConfig> {
        let first = self
            .auth
            .first()
            .ok_or_else(|| anyhow::anyhow!("--auth USER:PASS is required"))?;
        let (uid, password) = parse_auth(first)?;
        anyhow::ensure!(
            self.server_url.is_some() || self.url.is_some(),
            "client needs --server (WebTransport) and/or --url (HTTPS fallback)"
        );
        warn_open_inbound("--bind", &self.bind, self.inbound_auth.is_some());
        if let Some(hb) = &self.http_bind {
            warn_open_inbound("--http-bind", hb, self.inbound_auth.is_some());
        }
        // --sni / --pin validation (F-6): both are direct-path masquerade
        // knobs; --wss routing relies on the real SNI so masquerading there
        // would break CF routing, and --pin replaces --skip-verify outright.
        let pin = match &self.pin {
            Some(raw) => {
                let fp = parse_fingerprint(raw)?;
                anyhow::ensure!(
                    !self.skip_verify,
                    "--pin and --skip-verify are mutually exclusive: --pin is the stronger check"
                );
                Some(fp)
            }
            None => None,
        };
        if let Some(sni) = &self.sni {
            anyhow::ensure!(
                sni.len() <= 253 && !sni.is_empty(),
                "--sni must be a hostname (1..=253 chars)"
            );
            anyhow::ensure!(
                !sni.starts_with('.') && !sni.ends_with('.') && !sni.contains(".."),
                "--sni '{sni}' is not a valid hostname"
            );
            anyhow::ensure!(
                sni.chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_'),
                "--sni '{sni}' must be ASCII hostname characters [A-Za-z0-9.-_]"
            );
            // Masquerading SNI over wss would break CF's origin routing (CF
            // routes by real SNI); the fallback URL scheme decides transport.
            if let Some(fb) = &self.url {
                anyhow::ensure!(
                    !fb.starts_with("wss://") && !fb.starts_with("ws://"),
                    "--sni cannot masquerade a wss:// fallback URL: Cloudflare routes by \
                     the real SNI"
                );
            }
            anyhow::ensure!(
                pin.is_some() || self.skip_verify,
                "--sni requires --pin (recommended) or --skip-verify: the server certificate \
                 cannot match the masquerade name, so identity must be pinned explicitly"
            );
        }
        Ok(ClientConfig {
            wt_url: self.server_url.clone(),
            fb_url: self.url.clone(),
            socks_bind: self.bind.clone(),
            http_bind: self.http_bind.clone(),
            inbound_auth: match &self.inbound_auth {
                Some(raw) => Some(parse_inbound_auth(raw)?),
                None => None,
            },
            conns: self.conns.clamp(1, 8),
            uid,
            password,
            skip_verify: self.skip_verify,
            sni: self.sni.clone(),
            pin,
            recv_window: recv_window_bytes(self.recv_window_mb)?,
            health: self.health.clone(),
        })
    }

    pub fn server_config(&self) -> anyhow::Result<ServerConfig> {
        anyhow::ensure!(
            self.listen.is_some() || self.fallback_listen.is_some(),
            "server needs --listen (WebTransport) and/or --fallback-listen (HTTPS fallback)"
        );
        if let Some(l) = &self.listen {
            warn_listen_ip_ignored(l);
        }
        let cert = if self.self_signed {
            CertSource::SelfSigned
        } else {
            match (&self.cert, &self.key) {
                (Some(c), Some(k)) => {
                    // Fail before any listener binds (P2-3): a typo'd cert path
                    // must not surface as a mid-startup TLS error.
                    anyhow::ensure!(
                        std::path::Path::new(c).is_file(),
                        "cert file not found: {c}"
                    );
                    anyhow::ensure!(std::path::Path::new(k).is_file(), "key file not found: {k}");
                    CertSource::Files {
                        cert: c.clone(),
                        key: k.clone(),
                    }
                }
                _ => anyhow::bail!("server needs --cert/--key (or --self-signed for dev)"),
            }
        };
        let mut users = Vec::new();
        for a in &self.auth {
            users.push(parse_auth(a)?);
        }
        Ok(ServerConfig {
            listen: self.listen.clone(),
            cert,
            fallback_listen: self.fallback_listen.clone(),
            http_listen: self.http_listen.clone(),
            acme_dir: self.acme_dir.clone(),
            path: normalize_path(&self.path),
            users,
            max_sessions: self.max_sessions.max(1),
            rate_mbps: self.rate_mbps,
            idle_secs: self.idle_secs.max(5),
            allow_private_targets: self.allow_private_targets,
            max_unauth: self.max_unauth.max(1),
            recv_window: recv_window_bytes(self.recv_window_mb)?,
            shutdown_grace: self.shutdown_grace,
            health: self.health.clone(),
        })
    }
}

fn normalize_path(p: &str) -> String {
    let p = p.trim();
    if p.is_empty() || p == "/" {
        "/api/ppp".to_string()
    } else if p.starts_with('/') {
        p.to_string()
    } else {
        format!("/{p}")
    }
}

fn recv_window_bytes(mb: u64) -> anyhow::Result<u32> {
    anyhow::ensure!(
        (1..=64).contains(&mb),
        "--recv-window must be 1..=64 MB, got {mb}"
    );
    Ok(mb as u32 * 1024 * 1024)
}

/// Parse a `--pin` SHA-256 certificate fingerprint: 64 hex chars (colons
/// tolerated between byte pairs for readability, e.g. OpenSSL output).
fn parse_fingerprint(raw: &str) -> anyhow::Result<[u8; 32]> {
    let cleaned: String = raw.chars().filter(|c| *c != ':').collect();
    anyhow::ensure!(
        cleaned.len() == 64,
        "--pin must be a SHA-256 fingerprint: 64 hex chars (got {} chars)",
        cleaned.len()
    );
    let mut out = [0u8; 32];
    for (i, chunk) in cleaned.as_bytes().chunks(2).enumerate() {
        let hi = (chunk[0] as char).to_digit(16).ok_or_else(|| {
            anyhow::anyhow!("--pin: invalid hex character '{}'", chunk[0] as char)
        })?;
        let lo = (chunk[1] as char).to_digit(16).ok_or_else(|| {
            anyhow::anyhow!("--pin: invalid hex character '{}'", chunk[1] as char)
        })?;
        out[i] = ((hi << 4) | lo) as u8;
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Config file (P2): `KEY = VALUE` lines whose KEY is the verbatim long CLI
// option name, so the file shares the parameter table in docs/手册.md with no
// mapping table to keep in sync.
// ---------------------------------------------------------------------------

/// Pull `--config [path]` / `--config=[path]` out of raw argv. It must be
/// handled before `Cli` parsing because the file's contents are prepended to
/// the rest of the argv; clap would otherwise choke on the unknown ordering.
/// The returned vec keeps argv[0] (program name) where it was.
pub fn extract_config_arg(mut args: Vec<String>) -> anyhow::Result<(Option<String>, Vec<String>)> {
    let mut config: Option<String> = None;
    let mut i = 1;
    while i < args.len() {
        let a = &args[i];
        if a == "--config" {
            let v = args
                .get(i + 1)
                .ok_or_else(|| anyhow::anyhow!("--config needs a file path"))?;
            if config.is_some() {
                anyhow::bail!("--config given twice");
            }
            config = Some(v.clone());
            args.drain(i..=i + 1);
            continue; // re-examine the slot (the value was consumed)
        }
        if let Some(v) = a.strip_prefix("--config=") {
            if config.is_some() {
                anyhow::bail!("--config given twice");
            }
            config = Some(v.to_string());
            args.remove(i);
            continue;
        }
        i += 1;
    }
    Ok((config, args))
}

/// argv fragment for the given config source: explicit path (must exist),
/// else `./newppp.conf` when present, else nothing. Keys are validated
/// against the `Cli` definition itself, so this stays in sync with the CLI.
pub fn file_args(config_path: Option<&str>) -> anyhow::Result<Vec<String>> {
    let path = match config_path {
        Some(p) => p,
        None => {
            const DEFAULT: &str = "newppp.conf";
            if !std::path::Path::new(DEFAULT).is_file() {
                return Ok(Vec::new());
            }
            DEFAULT
        }
    };
    anyhow::ensure!(
        std::path::Path::new(path).is_file(),
        "config file not found: {path}"
    );
    let (argv, has_creds) = parse_config_file(path)?;
    if has_creds {
        maybe_warn_creds(path);
    }
    Ok(argv)
}

fn parse_config_file(path: &str) -> anyhow::Result<(Vec<String>, bool)> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| anyhow::Error::new(e).context(format!("read config file {path}")))?;
    // BOM (Windows 记事本保存的 UTF-8 文件带 \uFEFF) 泄入首行的 key。
    let text = text.strip_prefix('\u{feff}').unwrap_or(&text).to_string();

    // The long option names are taken from the Cli derive itself — the file
    // and `newppp --help` can never drift apart.
    let (longs, bools, appends) = clap_option_tables();

    let mut out = Vec::new();
    let mut has_creds = false;
    for (idx, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (key, value) = match line.split_once('=') {
            Some((k, v)) => {
                let k = k.trim();
                anyhow::ensure!(
                    !k.is_empty() && !k.contains(' '),
                    "{path}:{}: key must be a single option name",
                    idx + 1
                );
                (k, parse_value(v.trim()))
            }
            None => (line, None),
        };
        anyhow::ensure!(
            longs.contains(key),
            "{path}:{}: unknown option '{key}' — use the long CLI option names (see docs/手册.md)",
            idx + 1
        );
        if key == "auth" {
            has_creds = true;
        }
        // Later lines override earlier ones for single-value options (clap
        // itself errors on repeats, so we do the last-wins merge here).
        if !appends.contains(key) {
            remove_earlier_option(&mut out, key);
        }
        if key == "mode" {
            let v = value.as_deref().ok_or_else(|| {
                anyhow::anyhow!("{path}:{}: mode needs a value (server|client)", idx + 1)
            })?;
            out.push(match v {
                "server" => "-s".to_string(),
                "client" => "-c".to_string(),
                other => anyhow::bail!(
                    "{path}:{}: mode must be 'server' or 'client', got '{other}'",
                    idx + 1
                ),
            });
        } else if bools.contains(key) {
            match value.as_deref() {
                None | Some("true") => out.push(format!("--{key}")),
                Some(v) => anyhow::bail!(
                    "{path}:{}: '{key}' is an on/off switch, drop the value (got '{v}')",
                    idx + 1
                ),
            }
        } else {
            anyhow::ensure!(
                value.is_some(),
                "{path}:{}: option '{key}' needs a value (KEY = VALUE)",
                idx + 1
            );
            out.push(format!("--{key}"));
            out.push(value.expect("checked present"));
        }
    }
    Ok((out, has_creds))
}

/// `KEY = value`: whole-token quotes are stripped (their remainder is a
/// comment), anything else is kept byte-for-byte — `#` and spaces count as
/// value content for an unquoted value.
fn parse_value(v: &str) -> Option<String> {
    if v.is_empty() {
        return None;
    }
    let first = v.as_bytes()[0];
    if first == b'\'' || first == b'"' {
        if let Some(len) = v[1..].find(first as char) {
            return Some(v[1..1 + len].to_string()); // closing quote found: rest is a comment
        }
    }
    if v.len() >= 2 {
        let b = v.as_bytes();
        let last = b[b.len() - 1];
        if first == last && (first == b'\'' || first == b'"') {
            return Some(v[1..v.len() - 1].to_string());
        }
    }
    Some(v.to_string())
}

/// (long option names, bool switches, repeat-append options) — derived from
/// the `Cli` definition itself so the config grammar cannot drift from the CLI.
fn clap_option_tables() -> (
    std::collections::HashSet<String>,
    std::collections::HashSet<String>,
    std::collections::HashSet<String>,
) {
    use clap::CommandFactory;
    let cmd = Cli::command();
    let mut longs = std::collections::HashSet::new();
    let mut bools = std::collections::HashSet::new();
    let mut appends = std::collections::HashSet::new();
    for a in cmd.get_arguments() {
        if let Some(l) = a.get_long() {
            let owned = l.to_string();
            match a.get_action() {
                clap::ArgAction::SetTrue | clap::ArgAction::SetFalse => {
                    bools.insert(owned.clone());
                    longs.insert(owned);
                }
                clap::ArgAction::Append => {
                    appends.insert(owned.clone());
                    longs.insert(owned);
                }
                _ => {
                    longs.insert(owned);
                }
            }
        }
    }
    longs.insert("mode".to_string()); // mode = server | client -> -s / -c
    (longs, bools, appends)
}

/// Erase every earlier occurrence of `--key` (and, when the option takes a
/// separate value, that value token) so a later occurrence can win without
/// clap flagging a duplicate.
fn remove_earlier_option(out: &mut Vec<String>, key: &str) {
    let bare = format!("--{key}");
    let inline = format!("--{key}=");
    let mut j = 0;
    while j < out.len() {
        if out[j] == bare {
            out.remove(j);
            // the following token is a value unless it looks like another
            // option or a switched-mode argument
            if j < out.len() && !out[j].starts_with('-') {
                out.remove(j);
            }
        } else if out[j].starts_with(&inline) {
            out.remove(j);
        } else {
            j += 1;
        }
    }
}

/// Passwords live in the file text (that is the whole point): flag group/other
/// permissions instead of letting a casual `ls -l` reveal them. Unix only;
/// other platforms have no portable mode bits.
#[cfg(unix)]
fn maybe_warn_creds(path: &str) {
    use std::os::unix::fs::PermissionsExt;
    match std::fs::metadata(path).map(|m| m.permissions().mode()) {
        Ok(mode) if mode & 0o077 != 0 => {
            tracing::warn!(
                "config file {path} is readable by group/other while it contains \
                 passwords — run: chmod 600 {path}"
            );
        }
        Err(e) => {
            tracing::warn!("config file {path}: cannot check permissions: {e}");
        }
        _ => {}
    }
}

#[cfg(not(unix))]
fn maybe_warn_creds(_path: &str) {}

/// Commands supplied on the command line override the config file; a mode in
/// both places (`mode = server` + `-c`) is contradictory, so the file's mode
/// loses. Repeat-append options (`--auth`) are叠加 — only single-value
/// switches are overridden here (the file's sheer purpose stays intact).
pub fn strip_cli_overridden(file_args: &mut Vec<String>, cli_args: &[String]) {
    let (longs, bools, appends) = clap_option_tables();
    let mut override_keys: std::collections::HashSet<String> = std::collections::HashSet::new();
    let cli_has_mode = cli_args.iter().any(|a| a == "-c" || a == "-s");
    let mut i = 0;
    while i < cli_args.len() {
        let tok = cli_args[i].as_str();
        if let Some(rest) = tok.strip_prefix("--") {
            let (key, inline) = match rest.split_once('=') {
                Some((k, _)) => (k, true),
                None => (rest, false),
            };
            if longs.contains(key) && !appends.contains(key) {
                override_keys.insert(key.to_string());
                if inline || bools.contains(key) || rest.is_empty() {
                    i += 1; // no further value is consumed
                    continue;
                }
                // `--key value`: the value is not itself an option
                if i + 1 < cli_args.len() && !cli_args[i + 1].starts_with('-') {
                    i += 2;
                    continue;
                }
            }
        }
        i += 1;
    }
    for key in override_keys {
        remove_earlier_option(file_args, &key);
    }
    if cli_has_mode {
        file_args.retain(|a| a != "-c" && a != "-s");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_conf(content: &str) -> std::path::PathBuf {
        static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "newppp-cfg-test-{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("newppp.conf");
        std::fs::write(&path, content).unwrap();
        path
    }

    #[test]
    fn parses_values_bools_quotes_comments() {
        let p = write_conf(
            "# full-line comment\n\
             \n\
             mode = 'server'\n\
             auth  = 2233:mvNn\n\
             auth  = \"bob:hunter2\"        # trailing content is kept raw in the value\n\
             listen = 0.0.0.0:443\n\
             fallback-listen = 0.0.0.0:8443\n\
             skip-verify\n\
             ",
        );
        let (args, has_creds) = parse_config_file(p.to_str().unwrap()).unwrap();
        assert!(has_creds, "auth keys must flag creds");
        assert_eq!(
            args,
            vec![
                "-s",
                "--auth",
                "2233:mvNn",
                "--auth",
                "bob:hunter2",
                "--listen",
                "0.0.0.0:443",
                "--fallback-listen",
                "0.0.0.0:8443",
                "--skip-verify",
            ]
        );
        let cli = Cli::try_parse_from(
            std::iter::once("newppp".to_string()).chain(args.iter().map(|s| s.to_string())),
        )
        .unwrap();
        assert!(cli.server);
        assert_eq!(cli.auth.len(), 2);
        assert!(cli.skip_verify);
    }

    #[test]
    fn unknown_key_names_file_and_line() {
        let p = write_conf("mode = server\nlistn = 1:2\n");
        let e = parse_config_file(p.to_str().unwrap()).unwrap_err();
        let msg = format!("{e:#}");
        assert!(msg.contains("2") && msg.contains("listn"), "{msg}");
    }

    #[test]
    fn mode_value_is_validated() {
        let p = write_conf("mode = gateway\n");
        let e = parse_config_file(p.to_str().unwrap()).unwrap_err();
        assert!(format!("{e:#}").contains("'server' or 'client'"), "{e:#}");
    }

    #[test]
    fn boolean_switch_rejects_a_value() {
        let p = write_conf("skip-verify = true-ish\n");
        let e = parse_config_file(p.to_str().unwrap()).unwrap_err();
        assert!(format!("{e:#}").contains("on/off switch"), "{e:#}");
    }

    #[test]
    fn quoting_rules() {
        // quoted value + trailing comment: the comment is dropped
        let p = write_conf("time = 'https://a.b/c'  # comment\n");
        let (args, _) = parse_config_file(p.to_str().unwrap()).unwrap();
        assert_eq!(args, vec!["--time", "https://a.b/c"]);

        // unterminated stray quote: kept raw (no silent corruption)
        let p2 = write_conf("time = 'oops\n");
        let (args2, _) = parse_config_file(p2.to_str().unwrap()).unwrap();
        assert_eq!(args2, vec!["--time", "'oops"]);

        // unquoted value: inline `#` and spaces are content; `--path` is a
        // real option so assert on it directly
        let p3 = write_conf("path = a b'c # not-a-tag\n");
        let (args3, _) = parse_config_file(p3.to_str().unwrap()).unwrap();
        assert_eq!(args3, vec!["--path", "a b'c # not-a-tag"]);
    }

    #[test]
    fn extract_config_arg_forms() {
        let run = |args: Vec<&str>| {
            let owned: Vec<String> = args.iter().map(|s| s.to_string()).collect();
            let (cfg, rest) = extract_config_arg(owned).unwrap();
            (cfg, rest)
        };
        let (cfg, rest) = run(vec![
            "newppp",
            "--config",
            "/x/y.conf",
            "-s",
            "--auth",
            "a:b",
        ]);
        assert_eq!(cfg.as_deref(), Some("/x/y.conf"));
        assert_eq!(rest, vec!["newppp", "-s", "--auth", "a:b"]);

        let (cfg, rest) = run(vec!["newppp", "--config=/x/y.conf", "-s"]);
        assert_eq!(cfg.as_deref(), Some("/x/y.conf"));
        assert_eq!(rest, vec!["newppp", "-s"]);

        let (cfg, rest) = run(vec!["newppp", "-s", "--auth", "a:b"]);
        assert_eq!(cfg, None);
        assert_eq!(rest, vec!["newppp", "-s", "--auth", "a:b"]);
    }

    /// The documented precedence: later args win, and a mode contradiction
    /// from the file + CLI resolves to the CLI's mode.
    #[test]
    fn cli_overrides_file_and_mode_conflict_resolves() {
        let p = write_conf("mode = server\nlisten = 0.0.0.0:443\nmax-sessions = 100\nauth = a:b\n");
        let mut file_args = parse_config_file(p.to_str().unwrap()).unwrap().0;
        let cli_args: Vec<String> = vec!["-s", "--listen", "0.0.0.0:9999"]
            .into_iter()
            .map(String::from)
            .collect();
        strip_cli_overridden(&mut file_args, &cli_args);
        assert!(!file_args.contains(&"-c".to_string()) || true);
        let cli = Cli::try_parse_from(
            std::iter::once("newppp".to_string())
                .chain(file_args.iter().map(|s| s.to_string()))
                .chain(cli_args.iter().map(|s| s.to_string())),
        )
        .unwrap();
        assert!(cli.server && !cli.client, "CLI mode must win");
        assert_eq!(
            cli.listen.as_deref(),
            Some("0.0.0.0:9999"),
            "CLI listen beats file"
        );
        assert_eq!(cli.auth.len(), 1, "file auth kept");
    }

    // ---- F-6: --sni / --pin validation ----

    fn client_cli(extra: &[&str]) -> Cli {
        let mut args = vec!["newppp", "-c", "--auth", "a:b", "--server", "https://h:443"];
        args.extend_from_slice(extra);
        Cli::try_parse_from(args.iter().map(|s| s.to_string())).unwrap()
    }

    #[test]
    fn sni_requires_pin_or_skip_verify() {
        let e = client_cli(&["--sni", "cdn.example.com"])
            .client_config()
            .unwrap_err();
        assert!(format!("{e:#}").contains("--pin"), "{e:#}");
    }

    #[test]
    fn sni_with_pin_parses() {
        let fp = "ab".repeat(32);
        let cfg = client_cli(&["--sni", "cdn.example.com", "--pin", &fp])
            .client_config()
            .unwrap();
        assert_eq!(cfg.sni.as_deref(), Some("cdn.example.com"));
        assert_eq!(cfg.pin.unwrap()[0], 0xab);
    }

    #[test]
    fn pin_rejects_skip_verify() {
        let fp = "ab".repeat(32);
        let e = client_cli(&["--pin", &fp, "--skip-verify"])
            .client_config()
            .unwrap_err();
        assert!(format!("{e:#}").contains("mutually exclusive"), "{e:#}");
    }

    #[test]
    fn pin_without_sni_is_valid() {
        let fp = "ab".repeat(32);
        let cfg = client_cli(&["--pin", &fp]).client_config().unwrap();
        assert!(cfg.sni.is_none());
        assert_eq!(cfg.pin.unwrap()[31], 0xab);
    }

    #[test]
    fn pin_fingerprint_format_validated() {
        // wrong length
        let e = client_cli(&["--pin", "abcd"]).client_config().unwrap_err();
        assert!(format!("{e:#}").contains("64 hex"), "{e:#}");
        // non-hex
        let bad = "zz".repeat(32);
        let e = client_cli(&["--pin", &bad]).client_config().unwrap_err();
        assert!(format!("{e:#}").contains("invalid hex"), "{e:#}");
        // OpenSSL-style colons tolerated
        let colons = "ab:".repeat(31) + "ab";
        let cfg = client_cli(&["--pin", &colons]).client_config().unwrap();
        assert_eq!(cfg.pin.unwrap()[0], 0xab);
    }

    #[test]
    fn sni_hostname_validated() {
        let fp = "ab".repeat(32);
        // empty / too long / bad chars
        for bad in ["", &"a".repeat(254), "has space", "bad//slash"] {
            let e = client_cli(&["--sni", bad, "--pin", &fp])
                .client_config()
                .unwrap_err();
            assert!(!format!("{e:#}").is_empty(), "sni '{bad}' must be rejected");
        }
        // valid with underscore (wildcard-style labels are common)
        client_cli(&["--sni", "my_host.example.com", "--pin", &fp])
            .client_config()
            .unwrap();
    }

    #[test]
    fn sni_rejects_wss_fallback() {
        let fp = "ab".repeat(32);
        let e = Cli::try_parse_from(
            [
                "newppp",
                "-c",
                "--auth",
                "a:b",
                "--url",
                "wss://cf.example/api/ppp",
                "--sni",
                "cdn.example.com",
                "--pin",
                fp.as_str(),
            ]
            .iter()
            .map(|s| s.to_string()),
        )
        .unwrap()
        .client_config()
        .unwrap_err();
        assert!(format!("{e:#}").contains("wss"), "{e:#}");
    }
}
