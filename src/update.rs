use std::net::IpAddr;

use crate::config::{Config, UpdateCredential, UpdateProviderType};
use anyhow::{bail, Result};
use reqwest::Method;

mod httpget {
    use std::{collections::HashMap, net::IpAddr};

    use anyhow::Result;
    use reqwest::blocking::Client;
    use strfmt::Format;

    use crate::config::UpdateCredential;

    use super::UpdateProvider;

    pub(super) struct HttpGetUpdateProvider {
        pub(crate) credential: Option<UpdateCredential>,
        pub(crate) url_template: String,
    }

    impl UpdateProvider for HttpGetUpdateProvider {
        #[tracing::instrument(skip(self), err)]
        fn update(&self, name: &str, ip: IpAddr) -> Result<bool> {
            let mut vars = HashMap::new();
            let ip = ip.to_string();
            vars.insert("name".to_string(), name);
            vars.insert("ip".to_string(), &ip);
            let url = self.url_template.format(&vars)?;
            tracing::debug!("url after rendered: {}", url);

            let mut req_builder = Client::new().get(url);

            req_builder = match &self.credential {
                Some(UpdateCredential::HttpBasicAuth(credential)) => {
                    req_builder.basic_auth(credential.username(), credential.password().as_ref())
                }
                Some(UpdateCredential::HttpBearerToken { token }) => req_builder.bearer_auth(token),
                None => req_builder,
            };

            req_builder.send()?.error_for_status()?;
            Ok(true)
        }
    }
}

mod httpplainbody {
    use std::{collections::HashMap, net::IpAddr};

    use anyhow::Result;
    use reqwest::{blocking::Client, header::CONTENT_TYPE, Method};
    use strfmt::Format;

    use crate::config::UpdateCredential;

    use super::UpdateProvider;

    pub(super) struct HttpPlainBodyUpdateProvider {
        pub(crate) credential: Option<UpdateCredential>,
        pub(crate) url: String,
        pub(crate) method: Method,
        pub(crate) content_type: String,
        pub(crate) body_template: String,
    }

    impl UpdateProvider for HttpPlainBodyUpdateProvider {
        #[tracing::instrument(skip(self), err)]
        fn update(&self, name: &str, ip: IpAddr) -> Result<bool> {
            let mut vars = HashMap::new();
            let ip = ip.to_string();
            vars.insert("name".to_string(), name);
            vars.insert("ip".to_string(), &ip);
            let body = self.body_template.format(&vars)?;
            tracing::debug!("body after rendered: {}", body);

            let mut req_builder = Client::new()
                .request(self.method.clone(), &self.url)
                .header(CONTENT_TYPE, &self.content_type)
                .body(body);

            req_builder = match &self.credential {
                Some(UpdateCredential::HttpBasicAuth(credential)) => {
                    req_builder.basic_auth(credential.username(), credential.password().as_ref())
                }
                Some(UpdateCredential::HttpBearerToken { token }) => req_builder.bearer_auth(token),
                None => req_builder,
            };

            req_builder.send()?.error_for_status()?;
            Ok(true)
        }
    }
}

mod cloudflare {
    use std::{collections::HashMap, net::IpAddr};

    use anyhow::{bail, Result};
    use reqwest::{
        blocking::{Client, RequestBuilder},
        header::CONTENT_TYPE,
    };
    use serde::{de::DeserializeOwned, Deserialize, Serialize};
    use strfmt::Format;

    use super::UpdateProvider;

    #[derive(Deserialize, Serialize)]
    struct DnsRecord {
        comment: Option<String>,
        name: String,
        proxied: bool,
        ttl: u32,
        content: String,
        #[serde(rename = "type")]
        record_type: String,
        id: Option<String>,
    }

    #[allow(dead_code)]
    #[derive(Deserialize)]
    struct DnsResponse<T, P> {
        errors: Vec<ErrorObject>,
        messages: Vec<MessageObject>,
        success: bool,
        result: T,
        result_info: P,
    }

    #[allow(dead_code)]
    #[derive(Deserialize, Debug)]
    struct ErrorObject {
        code: u32,
        message: String,
    }

    #[allow(dead_code)]
    #[derive(Deserialize, Debug)]
    struct MessageObject {
        code: u32,
        message: String,
    }

    #[allow(dead_code)]
    #[derive(Deserialize, Debug)]
    struct PageInfo {
        count: usize,
        page: usize,
        per_page: usize,
        total_count: usize,
    }

    pub(super) struct CloudflareUpdateProvider {
        pub(crate) token: String,
        pub(crate) zone_id: String,
        pub(crate) proxied: bool,
        pub(crate) ttl: Option<u32>,
        pub(crate) comment: Option<String>,
    }

    impl CloudflareUpdateProvider {
        const GET_OR_POST_URL_TEMPLATE: &str =
            "https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records";
        const OTHER_URL_TEMPLATE: &str =
            "https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records/{dns_record_id}";

        fn record_type(is_v6: bool) -> &'static str {
            if is_v6 {
                "AAAA"
            } else {
                "A"
            }
        }

        fn call<T, P>(&self, req_builder: RequestBuilder) -> Result<DnsResponse<T, P>>
        where
            T: DeserializeOwned,
            P: DeserializeOwned,
        {
            let response = req_builder.send()?;

            let err = response.error_for_status_ref().err();
            let response_body = response.bytes()?;
            tracing::debug!("call cf, result: {:? }", response_body);
            if let Some(err) = err {
                return Err(From::from(err));
            }

            let response: DnsResponse<T, P> = serde_json::from_slice(&response_body)?;
            if !response.success {
                bail!("call cf with error: {:?}", response.errors);
            }
            Ok(response)
        }

        #[tracing::instrument(skip(self), err)]
        fn query(&self, name: &str, is_v6: bool) -> Result<Option<DnsRecord>> {
            let mut vars = HashMap::new();
            vars.insert("zone_id".to_string(), self.zone_id.as_str());
            let url = Self::GET_OR_POST_URL_TEMPLATE.format(&vars)?;
            tracing::debug!("url after rendered: {}", url);

            let req_builder = Client::new()
                .get(url)
                .bearer_auth(&self.token)
                .query(&[("name", name), ("type", Self::record_type(is_v6))]);

            let mut response: DnsResponse<Vec<DnsRecord>, PageInfo> = self.call(req_builder)?;
            // It should be contain zero or one record.
            Ok(response.result.pop())
        }

        #[tracing::instrument(skip(self), err)]
        fn create(&self, name: &str, ip: IpAddr) -> Result<()> {
            let mut vars = HashMap::new();
            vars.insert("zone_id".to_string(), self.zone_id.as_str());
            let url = Self::GET_OR_POST_URL_TEMPLATE.format(&vars)?;
            tracing::debug!("url after rendered: {}", url);

            let request = DnsRecord {
                comment: self.comment.clone(),
                name: name.to_string(),
                proxied: self.proxied,
                ttl: self.ttl.unwrap_or(300),
                content: ip.to_string(),
                record_type: Self::record_type(ip.is_ipv6()).to_string(),
                id: None,
            };

            let req_builder = Client::new()
                .post(url)
                .bearer_auth(&self.token)
                .header(CONTENT_TYPE, "application/json")
                .body(serde_json::to_string(&request)?);

            let _response: DnsResponse<DnsRecord, Option<()>> = self.call(req_builder)?;
            Ok(())
        }

        #[tracing::instrument(skip(self, old), err)]
        fn update(&self, mut old: DnsRecord, ip: IpAddr) -> Result<()> {
            let id = if let Some(id) = old.id.take() {
                id
            } else {
                bail!("no id in old dns record");
            };
            let mut vars = HashMap::new();
            vars.insert("zone_id".to_string(), self.zone_id.as_str());
            vars.insert("dns_record_id".to_string(), id.as_str());
            let url = Self::OTHER_URL_TEMPLATE.format(&vars)?;
            tracing::debug!("url after rendered: {}", url);

            old.proxied = self.proxied;
            old.content = ip.to_string();
            if !old.proxied {
                if let Some(ttl) = &self.ttl {
                    old.ttl = *ttl;
                }
            }
            old.comment = self.comment.clone();

            let req_builder = Client::new()
                .put(url)
                .bearer_auth(&self.token)
                .header(CONTENT_TYPE, "application/json")
                .body(serde_json::to_string(&old)?);

            let _response: DnsResponse<DnsRecord, Option<()>> = self.call(req_builder)?;

            Ok(())
        }
    }

    impl UpdateProvider for CloudflareUpdateProvider {
        #[tracing::instrument(skip(self), err)]
        fn update(&self, name: &str, ip: IpAddr) -> Result<bool> {
            match self.query(name, ip.is_ipv6())? {
                Some(old) => {
                    if old.content != ip.to_string()
                        || old.proxied != self.proxied
                        || self
                            .ttl
                            // with proxied, the ttl can't be changed.
                            .map(|t| !self.proxied && t != old.ttl)
                            .unwrap_or(false)
                        || self.comment != old.comment
                    {
                        self.update(old, ip)?
                    } else {
                        return Ok(false);
                    }
                }
                None => self.create(name, ip)?,
            }
            Ok(true)
        }
    }
}

fn find_optional_update_credential(
    config: &Config,
    credential: &Option<String>,
) -> Result<Option<UpdateCredential>> {
    if let Some(credential) = credential {
        Ok(Some(find_update_credential(config, credential)?))
    } else {
        Ok(None)
    }
}

fn find_update_credential(config: &Config, credential: &String) -> Result<UpdateCredential> {
    if let Some(credential) = config.update_credentials().get(credential) {
        Ok(credential.clone())
    } else {
        bail!("Credential not found: {}", credential)
    }
}

pub fn init_update_provider(
    update_provider_type: &UpdateProviderType,
    config: &Config,
) -> Result<Box<dyn UpdateProvider>> {
    match update_provider_type {
        UpdateProviderType::HttpGet {
            credential,
            url_template,
        } => Ok(Box::new(httpget::HttpGetUpdateProvider {
            credential: find_optional_update_credential(config, credential)?,
            url_template: url_template.clone(),
        })),
        UpdateProviderType::HttpPlainBody {
            credential,
            url,
            method,
            content_type,
            body_template,
        } => {
            let method = match method.to_uppercase().as_str() {
                "POST" => Method::POST,
                "PUT" => Method::PUT,
                "PATCH" => Method::PATCH,
                _ => {
                    bail!("Unsupport method in HttpPlainBody: {}", method);
                }
            };
            Ok(Box::new(httpplainbody::HttpPlainBodyUpdateProvider {
                credential: find_optional_update_credential(config, credential)?,
                url: url.clone(),
                method,
                content_type: content_type.clone(),
                body_template: body_template.clone(),
            }))
        }
        UpdateProviderType::Cloudflare {
            credential,
            zone_id,
            proxied,
            ttl,
            comment,
        } => {
            let token = match find_update_credential(config, credential)? {
                UpdateCredential::HttpBasicAuth(_) => {
                    bail!("Only HttpBearerToken credential is supported when cloudflare is used.");
                }
                UpdateCredential::HttpBearerToken { token } => token.clone(),
            };
            Ok(Box::new(cloudflare::CloudflareUpdateProvider {
                token,
                zone_id: zone_id.clone(),
                proxied: proxied.unwrap_or(false),
                ttl: *ttl,
                comment: comment.clone(),
            }))
        }
    }
}

pub trait UpdateProvider {
    fn update(&self, name: &str, ip: IpAddr) -> Result<bool>;
}
