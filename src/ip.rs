use std::net::IpAddr;

use crate::{
    config::{Config, IpProviderType},
    DEFAULT_TIMEOUT,
};
use anyhow::{bail, Result};

mod ifconfigio {
    use std::{
        net::{IpAddr, Ipv4Addr, Ipv6Addr},
        time::Duration,
    };

    use super::IpProvider;
    use anyhow::{bail, Context, Result};
    use reqwest::blocking::Client;

    pub(super) struct IfconfigIoIpProvider {
        pub(super) url: String,
        pub(super) timeout: Duration,
    }

    impl IpProvider for IfconfigIoIpProvider {
        fn query(&self, is_v6: bool) -> Result<IpAddr> {
            let mut builder = Client::builder().timeout(self.timeout);
            if is_v6 {
                builder = builder.local_address(Some(Ipv6Addr::UNSPECIFIED.into()))
            } else {
                builder = builder.local_address(Some(Ipv4Addr::UNSPECIFIED.into()))
            }
            let response = builder.build()?.get(&self.url).send()?.error_for_status()?;
            let text = response.text()?;
            let ip = text
                .trim()
                .parse::<IpAddr>()
                .with_context(|| format!("invalid ip: {}", text))?;
            if is_v6 && ip.is_ipv4() {
                bail!("query v6 from {}, but got v4: {}", self.url, ip);
            }
            if !is_v6 && ip.is_ipv6() {
                bail!("query v4 from {}, but got v6: {}", self.url, ip);
            }
            Ok(ip)
        }
    }
}

mod sslipio {
    use std::{net::IpAddr, time::Duration};

    use crate::dns::DnsClient;

    use super::IpProvider;
    use anyhow::{bail, Result};
    use hickory_proto::rr::{RData, RecordType};

    pub(super) struct SslipIoIpProvider {
        pub(super) name_server_host: String,
        pub(super) name_server_port: Option<u16>,
        pub(super) name: String,
        pub(super) timeout: Duration,
    }

    impl IpProvider for SslipIoIpProvider {
        fn query(&self, is_v6: bool) -> Result<IpAddr> {
            let client = DnsClient::new(
                &self.name_server_host,
                self.name_server_port,
                self.timeout,
                true,
                false,
            )?;
            let dns_response = client.query(&self.name, RecordType::TXT, Some(is_v6))?;
            let mut ips = dns_response.answers().iter().filter_map(|r| {
                if let Some(data) = r.data() {
                    match data {
                        RData::TXT(txt) => {
                            let mut data = vec![];
                            for d in txt.txt_data() {
                                data.extend(d);
                            }
                            match String::from_utf8(data) {
                                Ok(s) => match s.trim_matches('"').parse::<IpAddr>() {
                                    Ok(ip) => Some(ip),
                                    Err(e) => {
                                        tracing::warn!(
                                            "txt data of {} is not a valid ip: {} , {}",
                                            self.name,
                                            s,
                                            e
                                        );
                                        None
                                    }
                                },
                                Err(e) => {
                                    tracing::warn!("invalid txt data of {}: {}", self.name, e);
                                    None
                                }
                            }
                        }
                        _ => None,
                    }
                } else {
                    None
                }
            });
            if let Some(ip) = ips.next() {
                Ok(ip)
            } else {
                bail!("no ip resolved");
            }
        }
    }
}

pub fn init_ip_provider(
    ip_provider_type: &IpProviderType,
    _config: &Config,
) -> Result<Box<dyn IpProvider>> {
    match ip_provider_type {
        IpProviderType::Static { ip } => Ok(Box::new(StaticIpProvider(*ip))),
        IpProviderType::IfconfigIo { url, timeout } => {
            Ok(Box::new(ifconfigio::IfconfigIoIpProvider {
                url: url.clone(),
                timeout: timeout.unwrap_or(DEFAULT_TIMEOUT),
            }))
        }
        IpProviderType::SslipIo {
            name_server_host,
            name_server_port,
            name,
            timeout,
        } => Ok(Box::new(sslipio::SslipIoIpProvider {
            name_server_host: name_server_host.clone(),
            name_server_port: *name_server_port,
            name: name.clone(),
            timeout: timeout.unwrap_or(DEFAULT_TIMEOUT),
        })),
    }
}

pub trait IpProvider {
    fn query(&self, is_v6: bool) -> Result<IpAddr>;
}

struct StaticIpProvider(IpAddr);

impl IpProvider for StaticIpProvider {
    fn query(&self, is_v6: bool) -> Result<IpAddr> {
        if is_v6 && self.0.is_ipv4() {
            bail!("ipv4 ip is provided in a v6 section");
        }
        if !is_v6 && self.0.is_ipv6() {
            bail!("ipv6 ip is provided in a v4 section");
        }
        Ok(self.0)
    }
}
