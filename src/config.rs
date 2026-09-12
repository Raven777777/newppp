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

    /// [client+server] NTP server for the internal clock (hourly SNTP sync,
    /// UTC). Hostname, host:port, or host:port:protocol
    #[arg(long = "time", value_name = "SERVER", default_value = "pool.ntp.org")]
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
    pub recv_window: u32,
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
    pub recv_window: u32,
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
            recv_window: recv_window_bytes(self.recv_window_mb)?,
        })
    }

    pub fn server_config(&self) -> anyhow::Result<ServerConfig> {
        anyhow::ensure!(
            self.listen.is_some() || self.fallback_listen.is_some(),
            "server needs --listen (WebTransport) and/or --fallback-listen (HTTPS fallback)"
        );
        let cert = if self.self_signed {
            CertSource::SelfSigned
        } else {
            match (&self.cert, &self.key) {
                (Some(c), Some(k)) => CertSource::Files {
                    cert: c.clone(),
                    key: k.clone(),
                },
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
            recv_window: recv_window_bytes(self.recv_window_mb)?,
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
