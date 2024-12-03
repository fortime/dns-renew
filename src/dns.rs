use std::{
    cell::LazyCell,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs},
    str::FromStr,
    time::Duration,
};

use anyhow::{bail, Result};
use hickory_proto::{
    iocompat::AsyncIoTokioAsStd,
    native_tls::TlsClientStreamBuilder,
    op::{Message, Query},
    rr::{DNSClass, Name, RecordType},
    tcp::TcpClientStream,
    udp::UdpClientStream,
    xfer::{
        DnsExchange, DnsHandle, DnsRequest, DnsResponse, DnsStreamHandle, FirstAnswer,
        SerialMessage,
    },
    Time, TokioTime,
};
use tokio::{
    net::{TcpStream, UdpSocket},
    runtime::Runtime,
};

thread_local! {
    static RT: LazyCell<Runtime> = LazyCell::new(|| tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("can't build tokio runtime"));
}

async fn query_via_udp(
    addr: SocketAddr,
    timeout: Duration,
    bind_addr: Option<SocketAddr>,
    request: DnsRequest,
) -> Result<DnsResponse> {
    let stream =
        UdpClientStream::<UdpSocket>::with_bind_addr_and_timeout(addr, bind_addr, timeout).await?;
    let (exchange, bg) = DnsExchange::from_stream::<_, TokioTime>(stream);
    tokio::spawn(bg);
    Ok(exchange.send(request).first_answer().await?)
}

async fn query_via_tcp(
    addr: SocketAddr,
    timeout: Duration,
    bind_addr: Option<SocketAddr>,
    request: DnsRequest,
) -> Result<DnsResponse> {
    let (connect, mut sender) =
        TcpClientStream::<AsyncIoTokioAsStd<TcpStream>>::with_bind_addr_and_timeout(
            addr, bind_addr, timeout,
        );
    // timeout is set in connection.
    let stream = connect.await?;
    sender.send(SerialMessage::new(request.to_vec()?, addr))?;

    let response_data = TokioTime::timeout(timeout, stream.first_answer()).await??;
    Ok(DnsResponse::from_message(response_data.to_message()?)?)
}

async fn query_via_tls(
    addr: SocketAddr,
    host: &str,
    timeout: Duration,
    bind_addr: Option<SocketAddr>,
    request: DnsRequest,
) -> Result<DnsResponse> {
    let mut builder = TlsClientStreamBuilder::<AsyncIoTokioAsStd<TcpStream>>::new();
    if let Some(bind_addr) = bind_addr {
        builder.bind_addr(bind_addr);
    }
    let (connect, mut sender) = builder.build(addr, host.to_string());
    let stream = TokioTime::timeout(timeout, connect).await??;
    sender.send(SerialMessage::new(request.to_vec()?, addr))?;

    let response_data = TokioTime::timeout(timeout, stream.first_answer()).await??;
    Ok(DnsResponse::from_message(response_data.to_message()?)?)
}

pub struct DnsClient {
    host: String,
    port: Option<u16>,
    timeout: Duration,
    is_udp: bool,
    is_tls: bool,
}

impl DnsClient {
    pub fn new(
        host: impl Into<String>,
        port: Option<u16>,
        timeout: Duration,
        is_udp: bool,
        is_tls: bool,
    ) -> Result<Self> {
        if is_udp && is_tls {
            bail!("no support of udp with tls");
        }
        Ok(Self {
            host: host.into(),
            port,
            timeout,
            is_udp,
            is_tls,
        })
    }

    async fn do_query(
        &self,
        name: &str,
        record_type: RecordType,
        is_via_v6: Option<bool>,
        bind_addr: Option<SocketAddr>,
    ) -> Result<DnsResponse> {
        let port = self.port.unwrap_or(if self.is_tls { 853 } else { 53 });
        let addrs = (self.host.as_str(), port)
            .to_socket_addrs()?
            .filter(|addr| match is_via_v6 {
                Some(true) => addr.is_ipv6(),
                Some(false) => addr.is_ipv4(),
                None => true,
            });
        let bind_addr = bind_addr.or_else(|| match is_via_v6 {
            Some(true) => Some(SocketAddr::from((IpAddr::from(Ipv6Addr::UNSPECIFIED), 0))),
            Some(false) => Some(SocketAddr::from((IpAddr::from(Ipv4Addr::UNSPECIFIED), 0))),
            None => None,
        });

        let mut message = Message::new();
        let mut query = Query::query(Name::from_str(name)?, record_type);
        query.set_query_class(DNSClass::IN);
        message.set_recursion_desired(true).add_query(query);
        let request = DnsRequest::from(message);

        let mut has_tried = false;
        for addr in addrs {
            has_tried = true;
            let response = if self.is_tls {
                query_via_tls(addr, &self.host, self.timeout, bind_addr, request.clone()).await
            } else if self.is_udp {
                query_via_udp(addr, self.timeout, bind_addr, request.clone()).await
            } else {
                query_via_tcp(addr, self.timeout, bind_addr, request.clone()).await
            };
            match response {
                Ok(response) => return Ok(response),
                Err(e) => {
                    tracing::debug!(
                        "failed to resolve name[{}] in type[{}] with addr[{}]: {}, try next",
                        name,
                        record_type,
                        addr,
                        e,
                    )
                }
            }
        }

        if has_tried {
            bail!("failed to resolve name[{}]", name)
        }
        Ok(DnsResponse::from_message(Message::new())?)
    }

    pub fn query(
        &self,
        name: &str,
        record_type: RecordType,
        is_via_v6: Option<bool>,
    ) -> Result<DnsResponse> {
        RT.with(|rt| rt.block_on(self.do_query(name, record_type, is_via_v6, None)))
    }

    pub fn _query_with_bind_addr(
        &self,
        name: &str,
        record_type: RecordType,
        is_via_v6: Option<bool>,
        bind_addr: SocketAddr,
    ) -> Result<DnsResponse> {
        RT.with(|rt| rt.block_on(self.do_query(name, record_type, is_via_v6, Some(bind_addr))))
    }
}
