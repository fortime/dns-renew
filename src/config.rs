use std::{collections::HashMap, net::IpAddr, path::PathBuf, time::Duration};

use getset::{CopyGetters, Getters};
use serde::{Deserialize, Serialize};

#[derive(Deserialize, Getters)]
pub struct Config {
    #[getset(get = "pub")]
    name_conf_dir: PathBuf,

    #[getset(get = "pub")]
    name_state_dir: PathBuf,

    #[getset(get = "pub")]
    update_credentials: HashMap<String, UpdateCredential>,
}

#[derive(Clone, Deserialize)]
#[serde(tag = "type")]
pub enum UpdateCredential {
    HttpBasicAuth(HttpBasicAuthCredential),
    HttpBearerToken { token: String },
}

#[derive(Clone, Deserialize, Getters)]
pub struct HttpBasicAuthCredential {
    #[getset(get = "pub")]
    username: String,
    #[getset(get = "pub")]
    password: Option<String>,
}

#[derive(Deserialize, CopyGetters, Getters)]
pub struct NameConf {
    #[getset(get = "pub")]
    name: String,
    #[getset(get = "pub")]
    #[serde(with = "humantime_serde")]
    renew_interval: Duration,
    /// use config of v4/v6, if v6/v4 is not set.
    #[getset(get_copy = "pub")]
    shared: bool,
    #[getset(get = "pub")]
    v4: Option<NameProvidersConf>,
    #[getset(get = "pub")]
    v6: Option<NameProvidersConf>,
}

#[derive(Deserialize, CopyGetters, Getters)]
#[serde(tag = "type")]
pub struct NameProvidersConf {
    #[getset(get = "pub")]
    update_provider_type: UpdateProviderType,
    #[getset(get = "pub")]
    query_provider_type: QueryProviderType,
    #[getset(get = "pub")]
    ip_provider_type: IpProviderType,
    #[getset(get_copy = "pub")]
    enabled: bool,
}

#[derive(Deserialize)]
#[serde(tag = "type")]
pub enum UpdateProviderType {
    HttpGet {
        credential: Option<String>,
        url_template: String,
    },
    HttpPlainBody {
        credential: Option<String>,
        url: String,
        method: String,
        content_type: String,
        body_template: String,
    },
}

#[derive(Deserialize)]
#[serde(tag = "type")]
pub enum QueryProviderType {
    Dns(DnsQueryParams),
    DohGoogle(DohGoogleQueryParams),
    DohIetf(DohIetfQueryParams),
    Dot(DotQueryParams),
}

#[derive(Deserialize, CopyGetters, Getters)]
pub struct DnsQueryParams {
    #[getset(get = "pub")]
    name_server_host: String,
    #[getset(get = "pub")]
    name_server_port: Option<u16>,
    #[getset(get_copy = "pub")]
    #[serde(default, with = "humantime_serde")]
    timeout: Option<Duration>,
    #[getset(get_copy = "pub")]
    use_tcp: Option<bool>,
}

#[derive(Deserialize, CopyGetters, Getters)]
pub struct DohGoogleQueryParams {
    #[getset(get = "pub")]
    url: String,
    #[getset(get = "pub")]
    name_key: String,
    #[getset(get_copy = "pub")]
    #[serde(default, with = "humantime_serde")]
    timeout: Option<Duration>,
}

#[derive(Deserialize, CopyGetters, Getters)]
pub struct DohIetfQueryParams {
    #[getset(get = "pub")]
    url: String,
    #[getset(get_copy = "pub")]
    #[serde(default, with = "humantime_serde")]
    timeout: Option<Duration>,
}

#[derive(Deserialize, CopyGetters, Getters)]
pub struct DotQueryParams {
    #[getset(get = "pub")]
    name_server_host: String,
    #[getset(get = "pub")]
    name_server_port: Option<u16>,
    #[getset(get_copy = "pub")]
    #[serde(default, with = "humantime_serde")]
    timeout: Option<Duration>,
}

#[derive(Deserialize)]
#[serde(tag = "type")]
pub enum IpProviderType {
    Static {
        ip: IpAddr,
    },
    IfconfigIo {
        url: String,
        #[serde(default, with = "humantime_serde")]
        timeout: Option<Duration>,
    },
    SslipIo {
        name_server_host: String,
        name_server_port: Option<u16>,
        name: String,
        #[serde(default, with = "humantime_serde")]
        timeout: Option<Duration>,
    },
}

#[derive(Deserialize, Serialize, CopyGetters, Getters)]
pub struct NameState {
    #[getset(get = "pub")]
    name: String,
    #[getset(get_copy = "pub")]
    next: u64,
}

impl NameState {
    pub(crate) fn new(name: &str, next: u64) -> Self {
        Self {
            name: name.to_string(),
            next,
        }
    }
}
