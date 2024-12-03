use std::{net::IpAddr, time::Duration};

use crate::{
    config::{Config, QueryProviderType},
    dns::DnsClient,
    DEFAULT_TIMEOUT,
};
use anyhow::Result;
use dns::DnsQueryProvider;
use dohgoogle::DohGoogleQueryProvider;
use dohietf::DohIetfQueryProvider;
use dot::DotQueryProvider;
use hickory_proto::rr::{RData, RecordType};

mod dohgoogle {
    use std::{net::IpAddr, time::Duration};

    use anyhow::{bail, Result};
    use reqwest::{blocking::Client, Url};
    use serde::Deserialize;

    use super::QueryProvider;
    #[derive(Deserialize)]
    struct DohGoogleResponse {
        #[serde(rename = "Status")]
        status: i32,
        #[serde(rename = "Answer")]
        answer: Option<Vec<DohGoogleAnswer>>,
    }

    #[derive(Deserialize)]
    struct DohGoogleAnswer {
        data: IpAddr,
    }

    pub(super) struct DohGoogleQueryProvider {
        pub(super) url: String,
        pub(super) name_key: String,
        pub(super) timeout: Duration,
    }

    impl QueryProvider for DohGoogleQueryProvider {
        fn query(&self, name: &str, _is_v6: bool) -> Result<Vec<IpAddr>> {
            let url = Url::parse_with_params(&self.url, &[(&self.name_key, name)])?;
            let response_body = Client::new()
                .get(url.clone())
                .timeout(self.timeout)
                .send()?
                .error_for_status()?
                .bytes()?;

            tracing::debug!("query through DohGoogle returns: {:?}", response_body);
            let response: DohGoogleResponse = serde_json::from_slice(&response_body)?;
            // NOERROR: 0, NXDOMAIN: 3
            if response.status != 0 && response.status != 3 {
                bail!(
                    "status in response body of DohGoogle[{}] is: {}",
                    url,
                    response.status
                );
            }
            Ok(response
                .answer
                .unwrap_or_default()
                .iter()
                .map(|i| i.data)
                .collect())
        }
    }
}

mod dns {
    use std::{net::IpAddr, time::Duration};

    use anyhow::Result;

    use super::QueryProvider;

    pub(super) struct DnsQueryProvider {
        pub(super) name_server_host: String,
        pub(super) name_server_port: Option<u16>,
        pub(super) timeout: Duration,
        pub(super) use_tcp: bool,
    }

    impl QueryProvider for DnsQueryProvider {
        fn query(&self, name: &str, is_v6: bool) -> Result<Vec<IpAddr>> {
            super::query(
                &self.name_server_host,
                self.name_server_port,
                self.timeout,
                !self.use_tcp,
                false,
                name,
                is_v6,
            )
        }
    }
}

mod dohietf {
    use std::{net::IpAddr, str::FromStr, time::Duration};

    use anyhow::{Context, Result};
    use hickory_proto::{
        op::{Message, MessageType, Query},
        rr::{DNSClass, Name, RData, RecordType},
    };
    use reqwest::{blocking::Client, header::CONTENT_TYPE};

    use super::QueryProvider;

    pub(super) struct DohIetfQueryProvider {
        pub(super) url: String,
        pub(super) timeout: Duration,
    }

    impl QueryProvider for DohIetfQueryProvider {
        fn query(&self, name: &str, is_v6: bool) -> Result<Vec<IpAddr>> {
            let record_type = if is_v6 {
                RecordType::AAAA
            } else {
                RecordType::A
            };
            let mut query = Query::query(Name::from_str(name)?, record_type);
            query.set_query_class(DNSClass::IN);
            let mut message = Message::new();
            let body = message
                // per the RFC, a zero id allows for the HTTP packet to be cached better
                .set_id(0)
                .set_message_type(MessageType::Query)
                .set_recursion_desired(true)
                .add_query(query)
                .to_vec()
                .with_context(|| {
                    format!(
                        "failed to generate query message for name[{}], is_v6: {}",
                        name, is_v6
                    )
                })?;
            let response_body = Client::new()
                .post(&self.url)
                .header(CONTENT_TYPE, "application/dns-message")
                .timeout(self.timeout)
                .body(body)
                .send()?
                .error_for_status()?
                .bytes()?;

            let response_message = Message::from_vec(&response_body).with_context(|| {
                format!(
                    "failed to parse response from name[{}], is_v6: {}",
                    name, is_v6
                )
            })?;
            tracing::debug!("query through DohIetf returns: {:?}", response_message);

            Ok(response_message
                .answers()
                .iter()
                .filter_map(|r| {
                    if let Some(data) = r.data() {
                        match data {
                            RData::A(ip) => Some(ip.0.into()),
                            RData::AAAA(ip) => Some(ip.0.into()),
                            _ => None,
                        }
                    } else {
                        None
                    }
                })
                .collect())
        }
    }
}

mod dot {
    use std::{net::IpAddr, time::Duration};

    use anyhow::Result;

    use super::QueryProvider;

    pub(super) struct DotQueryProvider {
        pub(super) name_server_host: String,
        pub(super) name_server_port: Option<u16>,
        pub(super) timeout: Duration,
    }

    impl QueryProvider for DotQueryProvider {
        fn query(&self, name: &str, is_v6: bool) -> Result<Vec<IpAddr>> {
            super::query(
                &self.name_server_host,
                self.name_server_port,
                self.timeout,
                false,
                true,
                name,
                is_v6,
            )
        }
    }
}

fn query(
    server_host: &str,
    server_port: Option<u16>,
    timeout: Duration,
    is_udp: bool,
    is_tls: bool,
    name: &str,
    is_v6: bool,
) -> Result<Vec<IpAddr>> {
    let client = DnsClient::new(server_host, server_port, timeout, is_udp, is_tls)?;
    let record_type = if is_v6 {
        RecordType::AAAA
    } else {
        RecordType::A
    };
    let dns_response = client.query(name, record_type, Some(is_v6))?;
    Ok(dns_response
        .answers()
        .iter()
        .filter_map(|r| {
            if let Some(data) = r.data() {
                match data {
                    RData::A(ip) => Some(ip.0.into()),
                    RData::AAAA(ip) => Some(ip.0.into()),
                    _ => None,
                }
            } else {
                None
            }
        })
        .collect())
}

pub fn init_query_provider(
    query_provider_type: &QueryProviderType,
    _config: &Config,
) -> Result<Box<dyn QueryProvider>> {
    match query_provider_type {
        QueryProviderType::Dns(dns_query_params) => Ok(Box::new(DnsQueryProvider {
            name_server_host: dns_query_params.name_server_host().clone(),
            name_server_port: *dns_query_params.name_server_port(),
            timeout: dns_query_params.timeout().unwrap_or(DEFAULT_TIMEOUT),
            use_tcp: dns_query_params.use_tcp().unwrap_or(false),
        })),
        QueryProviderType::DohGoogle(doh_google_query_params) => {
            Ok(Box::new(DohGoogleQueryProvider {
                url: doh_google_query_params.url().clone(),
                name_key: doh_google_query_params.name_key().clone(),
                timeout: doh_google_query_params.timeout().unwrap_or(DEFAULT_TIMEOUT),
            }))
        }
        QueryProviderType::DohIetf(doh_ietf_query_params) => Ok(Box::new(DohIetfQueryProvider {
            url: doh_ietf_query_params.url().clone(),
            timeout: doh_ietf_query_params.timeout().unwrap_or(DEFAULT_TIMEOUT),
        })),
        QueryProviderType::Dot(dot_query_params) => Ok(Box::new(DotQueryProvider {
            name_server_host: dot_query_params.name_server_host().clone(),
            name_server_port: *dot_query_params.name_server_port(),
            timeout: dot_query_params.timeout().unwrap_or(DEFAULT_TIMEOUT),
        })),
    }
}

pub trait QueryProvider {
    fn query(&self, name: &str, is_v6: bool) -> Result<Vec<IpAddr>>;
}
