use std::{
    fs::{self, DirEntry},
    io,
    path::PathBuf,
    process,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{anyhow, Context, Result};
use clap::{command, Parser};
use config::{Config, NameConf, NameProvidersConf, NameState};
use figment::{
    providers::{Env, Format, Toml},
    Figment,
};
use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

mod config;
mod dns;
mod ip;
mod query;
mod update;

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// The path of config file.
    #[arg(
        short,
        long,
        value_name = "PATH",
        default_value = "/etc/dns-renew/dns-renew.toml"
    )]
    config: PathBuf,

    /// Dry run, only check if update is needed, no update will be performed.
    #[arg(long, default_missing_value = "true")]
    dry_run: bool,
}

fn init_config(args: &Args) -> Result<Config> {
    const ENV_PREFIX: &str = "DNS_RENEW_";

    let figment = Figment::new()
        .merge(Toml::file(&args.config))
        .merge(Env::raw().filter_map(|k| {
            if k.starts_with(ENV_PREFIX) {
                Some(k[ENV_PREFIX.len()..].into())
            } else {
                None
            }
        }));
    Ok(figment.extract()?)
}

fn init_log(config: &Config) -> Result<()> {
    let subscriber = tracing_subscriber::registry().with(EnvFilter::from_default_env());
    if config.log_timestamp().unwrap_or(true) {
        subscriber.with(fmt::layer()).try_init()?;
    } else {
        subscriber.with(fmt::layer().without_time()).try_init()?;
    }
    Ok(())
}

fn run(args: Args) -> Result<()> {
    let config = init_config(&args)?;

    init_log(&config)?;

    let childrens = config
        .name_conf_dir()
        .read_dir()
        .with_context(|| format!("{:?} not found", config.name_conf_dir()))?;

    for child in childrens {
        let span = tracing::info_span!(
            "renew_name",
            path = child
                .as_ref()
                .ok()
                .and_then(|c| c.path().to_str().map(ToString::to_string))
                .unwrap_or_else(|| "invalid path".to_string())
        );
        let _enter = span.enter();

        match renew_name(child, &config) {
            Ok(Some(name)) => tracing::info!("renew {name} successfully"),
            Ok(None) => tracing::info!("skip path"),
            Err(e) => tracing::error!("failed to renew: {:?}", e),
        }
    }
    Ok(())
}

fn next(interval: &Duration) -> Result<u64> {
    SystemTime::now()
        .checked_add(*interval)
        .ok_or_else(|| anyhow!("unable to get next time"))
        .and_then(|t| {
            t.duration_since(SystemTime::UNIX_EPOCH)
                .with_context(|| "failed to get timestamp in creating NameState".to_string())
        })
        .map(|t| t.as_secs())
}

fn read_state(state_path: &PathBuf, name_conf: &NameConf) -> Result<Option<NameState>> {
    let name_state = if state_path.exists() {
        Some(
            Figment::new()
                .merge(Toml::file(state_path))
                .extract::<NameState>()
                .with_context(|| {
                    format!("failed to read from name state file: {:?}", state_path)
                })?,
        )
    } else {
        None
    };

    let name_state = match name_state {
        Some(state) => {
            if state.name() != name_conf.name() {
                tracing::info!(
                    "name has been changed from [{}] to [{}] in state file",
                    state.name(),
                    name_conf.name()
                );
                NameState::new(name_conf.name(), next(name_conf.renew_interval())?)
            } else if state.next() > SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() {
                tracing::debug!("renew of [{}] is not due", name_conf.name());
                return Ok(None);
            } else {
                NameState::new(name_conf.name(), next(name_conf.renew_interval())?)
            }
        }
        None => NameState::new(name_conf.name(), next(name_conf.renew_interval())?),
    };
    Ok(Some(name_state))
}

fn renew_name(entry: io::Result<DirEntry>, config: &Config) -> Result<Option<String>> {
    let entry = entry?;
    let conf_path = entry.path();
    if !(entry.file_type()?.is_file()
        && conf_path.extension().filter(|&ext| ext == "toml").is_some())
    {
        return Ok(None);
    }

    tracing::debug!("reading NameConf from {:?}", conf_path);
    let name_conf = Figment::new()
        .merge(Toml::file(&conf_path))
        .extract::<NameConf>()
        .with_context(|| format!("failed to read from name config file: {:?}", conf_path))?;
    let state_path = config.name_state_dir().join(
        conf_path
            .file_stem()
            .ok_or_else(|| anyhow!("it should have a file name"))?,
    );

    let name_state = match read_state(&state_path, &name_conf)? {
        Some(s) => s,
        None => return Ok(None),
    };

    let v4_name_providers_conf = name_conf
        .v4()
        .as_ref()
        .or_else(|| {
            if name_conf.shared() {
                name_conf.v6().as_ref()
            } else {
                None
            }
        })
        .filter(|c| c.enabled());

    let v6_name_providers_conf = name_conf
        .v6()
        .as_ref()
        .or_else(|| {
            if name_conf.shared() {
                name_conf.v4().as_ref()
            } else {
                None
            }
        })
        .filter(|c| c.enabled());

    let mut updated = false;

    if let Some(name_providers_conf) = v4_name_providers_conf {
        updated |= renew(&name_conf, name_providers_conf, config, false)?;
    }

    if let Some(name_providers_conf) = v6_name_providers_conf {
        updated |= renew(&name_conf, name_providers_conf, config, true)?;
    }

    fs::write(&state_path, toml::to_string(&name_state)?)?;

    if !updated {
        Ok(None)
    } else {
        Ok(Some(name_conf.name().clone()))
    }
}

#[tracing::instrument(skip(name_conf, name_providers_conf, config), fields(name = name_conf.name()))]
fn renew(
    name_conf: &NameConf,
    name_providers_conf: &NameProvidersConf,
    config: &Config,
    is_v6: bool,
) -> Result<bool> {
    let query_provider =
        query::init_query_provider(name_providers_conf.query_provider_type(), config)?;

    let ips = query_provider.query(name_conf.name(), is_v6)?;
    tracing::debug!("current ips of domain: {:?}", ips);

    let ip_provider = ip::init_ip_provider(name_providers_conf.ip_provider_type(), config)?;
    let ip = ip_provider.query(is_v6)?;
    tracing::debug!("current ip: {}", ip);

    if ips.contains(&ip) {
        return Ok(false);
    }

    tracing::info!("{} is not in {:?}, ready to update", ip, ips);
    let update_provider =
        update::init_update_provider(name_providers_conf.update_provider_type(), config)?;
    update_provider.update(name_conf.name(), ip)
}

fn main() {
    let args = Args::parse();
    if let Err(e) = run(args) {
        eprintln!("run command failed: {e}");
        process::exit(1);
    }
}
