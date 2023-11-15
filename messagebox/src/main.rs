use std::{net::Ipv4Addr, path::PathBuf};

use anyhow::{Context, Result};
use clap::{arg, Parser};
use controller::LocationScheme;
use figment::{
    providers::{Format, Serialized, Yaml},
    Figment,
};
use messagebox::{
    messagebox::MessageBox, messagebox_listener::MessageBoxListener, MessageboxError,
};
use serde::{Deserialize, Serialize};
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
    let args = Args::parse();

    println!("Using config file {:?}", args.config_file);

    let cfg = Figment::new()
        .merge(Yaml::file(args.config_file.clone()))
        .merge(Serialized::defaults(args))
        .extract::<Config>()
        .context("Failed to load config")?;

    let watcher_oobi: LocationScheme =
        serde_json::from_str(&cfg.watcher_oobi).map_err(|e| MessageboxError::OobiParsingError)?;

    let data = MessageBox::setup(
        &cfg.db_path,
        &cfg.oobi_path,
        watcher_oobi,
        cfg.public_url,
        cfg.seed,
        cfg.server_key,
    )
    .await?;
    let messagebox_oobi = data.oobi();

    let listener = MessageBoxListener { messagebox: data };
    println!(
        "Messagebox is listening. It's oobi is: {}",
        serde_json::to_string(&messagebox_oobi).map_err(|_e| MessageboxError::OobiParsingError)?
    );
    listener
        .listen_http((Ipv4Addr::UNSPECIFIED, cfg.http_port))?
        .await?;
    Ok(())
}
