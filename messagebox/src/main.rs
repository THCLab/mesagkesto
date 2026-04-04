use std::{net::Ipv4Addr, path::PathBuf};

use anyhow::{Context, Result};
use clap::{arg, Parser};
use figment::{
    providers::{Format, Serialized, Yaml},
    Figment,
};
use keri_sdk::LocationScheme;
use messagebox::{
    db::Db, messagebox::MessageBox, messagebox_listener::MessageBoxListener, MessageboxError,
};
use serde::{Deserialize, Serialize};
use tracing::info;
use url::Url;

#[derive(Deserialize)]
pub struct Config {
    oobi_path: PathBuf,

    db_path: PathBuf,

    watcher_oobi: String,

    /// Public URL used to advertise itself to other actors using OOBI.
    public_url: Url,

    /// HTTP Listen port
    http_port: u16,

    /// Witness keypair seed
    seed: Option<String>,

    /// Firebase server key
    server_key: Option<String>,

    /// DauthZ state directory (enables authentication)
    dauthz_state_dir: Option<PathBuf>,

    /// Shared secret for signing MQTT JWTs (must match EMQX config)
    jwt_secret: Option<String>,

    /// MQTT broker WebSocket URL (e.g. ws://host:8083/mqtt)
    mqtt_url: Option<String>,
}

#[derive(Debug, Parser, Serialize)]
#[command(author, version, about)]
struct Args {
    #[arg(short = 'c', long, default_value = "messagebox.yml")]
    config_file: String,

    #[arg(short = 'd', long)]
    #[serde(skip_serializing_if = "Option::is_none")]
    oobi_path: Option<PathBuf>,

    #[arg(short = 'u', long)]
    #[serde(skip_serializing_if = "Option::is_none")]
    public_url: Option<Url>,

    #[arg(short = 'p', long)]
    #[serde(skip_serializing_if = "Option::is_none")]
    http_port: Option<u16>,

    #[arg(short = 's', long)]
    #[serde(skip_serializing_if = "Option::is_none")]
    seed: Option<String>,

    #[arg(short = 'k', long)]
    #[serde(skip_serializing_if = "Option::is_none")]
    server_key: Option<String>,
}

#[actix_web::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let args = Args::parse();

    info!(config_file = %args.config_file, "Loading configuration");

    let cfg = Figment::new()
        .merge(Yaml::file(args.config_file.clone()))
        .merge(Serialized::defaults(args))
        .extract::<Config>()
        .context("Failed to load config")?;

    let watcher_oobi: LocationScheme =
        serde_json::from_str(&cfg.watcher_oobi).map_err(|_e| MessageboxError::OobiParsingError)?;

    let db = Db::open(&cfg.db_path).expect("Failed to open database");

    let data = MessageBox::setup(
        db,
        &cfg.db_path,
        &cfg.oobi_path,
        watcher_oobi,
        cfg.public_url,
        cfg.seed,
        cfg.server_key,
        cfg.dauthz_state_dir.as_deref(),
        cfg.jwt_secret.clone(),
    )
    .await?;
    let messagebox_oobi = data.oobi();

    let listener = MessageBoxListener {
        messagebox: data,
        mqtt_url: cfg.mqtt_url,
    };
    info!(
        oobi = %serde_json::to_string(&messagebox_oobi).map_err(|_e| MessageboxError::OobiParsingError)?,
        "Messagebox is listening"
    );
    listener
        .listen_http((Ipv4Addr::UNSPECIFIED, cfg.http_port))?
        .await?;
    Ok(())
}
