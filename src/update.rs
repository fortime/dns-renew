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
        fn update(&self, name: &str, ip: IpAddr) -> Result<()> {
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
            Ok(())
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
        fn update(&self, name: &str, ip: IpAddr) -> Result<()> {
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
            Ok(())
        }
    }
}

fn find_update_credential(
    config: &Config,
    credential: &Option<String>,
) -> Result<Option<UpdateCredential>> {
    if let Some(credential) = credential {
        if let Some(credential) = config.update_credentials().get(credential) {
            Ok(Some(credential.clone()))
        } else {
            bail!("Credential not found: {}", credential)
        }
    } else {
        Ok(None)
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
            credential: find_update_credential(config, credential)?,
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
                credential: find_update_credential(config, credential)?,
                url: url.clone(),
                method,
                content_type: content_type.clone(),
                body_template: body_template.clone(),
            }))
        }
    }
}

pub trait UpdateProvider {
    fn update(&self, name: &str, ip: IpAddr) -> Result<()>;
}
