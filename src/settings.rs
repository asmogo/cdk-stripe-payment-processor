use figment::{
    providers::{Format, Serialized, Toml},
    Figment,
};
use serde::{Deserialize, Serialize};
use std::time::Duration;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct StripeSettings {
    pub api_key: String,
    #[serde(default)]
    pub account_id: String,
    #[serde(default)]
    pub stripe_version: String,
    #[serde(default = "default_stripe_timeout_ms")]
    pub timeout_ms: u64,
    #[serde(default)]
    pub webhook_secret: String,
    #[serde(default = "default_webhook_tolerance_seconds")]
    pub webhook_tolerance_seconds: i64,
    #[serde(default = "default_payment_timeout", with = "humantime_serde")]
    pub payment_timeout: Duration,
}

impl Default for StripeSettings {
    fn default() -> Self {
        Self {
            api_key: String::new(),
            account_id: String::new(),
            stripe_version: String::new(),
            timeout_ms: default_stripe_timeout_ms(),
            webhook_secret: String::new(),
            webhook_tolerance_seconds: default_webhook_tolerance_seconds(),
            payment_timeout: default_payment_timeout(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    #[serde(default)]
    pub stripe: StripeSettings,
    pub server_port: u16,
    // TLS config for gRPC server
    pub tls_enable: bool,
    pub tls_cert_path: String,
    pub tls_key_path: String,
    #[serde(default = "default_keep_alive_interval", with = "humantime_serde")]
    pub keep_alive_interval: Duration,
    #[serde(default = "default_keep_alive_timeout", with = "humantime_serde")]
    pub keep_alive_timeout: Duration,
    #[serde(default = "default_max_connection_age", with = "humantime_serde")]
    pub max_connection_age: Duration,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            stripe: StripeSettings::default(),
            server_port: 50051,
            tls_enable: false,
            tls_cert_path: "certs/server.crt".to_string(),
            tls_key_path: "certs/server.key".to_string(),
            keep_alive_interval: default_keep_alive_interval(),
            keep_alive_timeout: default_keep_alive_timeout(),
            max_connection_age: default_max_connection_age(),
        }
    }
}

impl Config {
    /// Load from config.toml (if present) and environment variables.
    /// Environment variables override file values.
    /// Supported env keys: STRIPE_API_KEY, STRIPE_ACCOUNT_ID, STRIPE_VERSION,
    /// STRIPE_TIMEOUT_MS, STRIPE_WEBHOOK_SECRET, STRIPE_WEBHOOK_TOLERANCE_SECONDS,
    /// STRIPE_PAYMENT_TIMEOUT, SERVER_PORT, TLS_ENABLE,
    /// TLS_CERT_PATH, TLS_KEY_PATH, KEEP_ALIVE_INTERVAL, KEEP_ALIVE_TIMEOUT, MAX_CONNECTION_AGE
    pub fn load() -> Self {
        // 1) Start with defaults + config.toml only if it exists
        let base: Config = Default::default();
        let mut fig = Figment::from(Serialized::defaults(base));
        if std::path::Path::new("config.toml").exists() {
            fig = fig.merge(Toml::file("config.toml"));
        }
        let mut cfg: Config = fig.extract().unwrap_or_default();

        // 2) Overlay environment variables explicitly
        if let Ok(v) = std::env::var("STRIPE_API_KEY") {
            cfg.stripe.api_key = v;
        }
        if let Ok(v) = std::env::var("STRIPE_ACCOUNT_ID") {
            cfg.stripe.account_id = v;
        }
        if let Ok(v) = std::env::var("STRIPE_VERSION") {
            cfg.stripe.stripe_version = v;
        }
        if let Ok(v) = std::env::var("STRIPE_TIMEOUT_MS") {
            cfg.stripe.timeout_ms = v.parse().unwrap_or(cfg.stripe.timeout_ms);
        }
        if let Ok(v) = std::env::var("STRIPE_WEBHOOK_SECRET") {
            cfg.stripe.webhook_secret = v;
        }
        if let Ok(v) = std::env::var("STRIPE_WEBHOOK_TOLERANCE_SECONDS") {
            cfg.stripe.webhook_tolerance_seconds = v.parse().unwrap_or(cfg.stripe.webhook_tolerance_seconds);
        }
        if let Ok(v) = std::env::var("STRIPE_PAYMENT_TIMEOUT") {
            cfg.stripe.payment_timeout = parse_duration_env(&v, cfg.stripe.payment_timeout);
        }
        if let Ok(v) = std::env::var("SERVER_PORT") {
            cfg.server_port = v.parse().unwrap_or(cfg.server_port);
        }
        if let Ok(v) = std::env::var("TLS_ENABLE") {
            cfg.tls_enable = matches!(v.as_str(), "1" | "true" | "TRUE" | "yes" | "YES");
        }
        if let Ok(v) = std::env::var("TLS_CERT_PATH") {
            cfg.tls_cert_path = v;
        }
        if let Ok(v) = std::env::var("TLS_KEY_PATH") {
            cfg.tls_key_path = v;
        }
        if let Ok(v) = std::env::var("KEEP_ALIVE_INTERVAL") {
            cfg.keep_alive_interval = parse_duration_env(&v, cfg.keep_alive_interval);
        }
        if let Ok(v) = std::env::var("KEEP_ALIVE_TIMEOUT") {
            cfg.keep_alive_timeout = parse_duration_env(&v, cfg.keep_alive_timeout);
        }
        if let Ok(v) = std::env::var("MAX_CONNECTION_AGE") {
            cfg.max_connection_age = parse_duration_env(&v, cfg.max_connection_age);
        }

        cfg
    }

    pub fn from_env() -> Self {
        Self::load()
    }
}

fn parse_duration_env(value: &str, current: Duration) -> Duration {
    humantime::parse_duration(value).unwrap_or(current)
}

fn default_keep_alive_interval() -> Duration {
    Duration::from_secs(30)
}

fn default_keep_alive_timeout() -> Duration {
    Duration::from_secs(10)
}

fn default_max_connection_age() -> Duration {
    Duration::from_secs(1800)
}

fn default_stripe_timeout_ms() -> u64 {
    15_000
}

fn default_webhook_tolerance_seconds() -> i64 {
    300 // 5 minutes
}

fn default_payment_timeout() -> Duration {
    Duration::from_secs(300) // 5 minutes
}