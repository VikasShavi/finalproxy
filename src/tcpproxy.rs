use pingora_core::listeners::Listeners;
use pingora_core::services::listening::Service;
use pingora_core::upstreams::peer::BasicPeer;
use std::os::unix::io;
use async_trait::async_trait;

use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::select;

use pingora::apps::ServerApp;
use pingora::connectors::TransportConnector;
use pingora::protocols::Stream;
use pingora::server::ShutdownWatch;
use pingora::protocols::l4::stream::Stream as L4Stream;
use pingora::protocols::IO;

pub fn proxy_service(addr: &str) -> Service<ProxyApp> {

    Service::with_listeners(
        "Proxy Service".to_string(),
        Listeners::tcp(addr),
        ProxyApp::new(),
    )
}

pub struct ProxyApp {
    client_connector: TransportConnector,
}

enum DuplexEvent {
    DownstreamRead(usize),
    UpstreamRead(usize),
}

impl ProxyApp {
    pub fn new() -> Self {
        ProxyApp {
            client_connector: TransportConnector::new(None),
        }
    }

    async fn duplex(&self, mut server_session: Stream, mut client_session: Stream) {
        let mut upstream_buf = [0; 1024];
        let mut downstream_buf = [0; 1024];

        loop {
            let downstream_read = server_session.read(&mut upstream_buf);
            let upstream_read = client_session.read(&mut downstream_buf);
            let event: DuplexEvent;
            select! {
                n = downstream_read => event
                    = DuplexEvent::DownstreamRead(n.unwrap()),
                n = upstream_read => event
                    = DuplexEvent::UpstreamRead(n.unwrap()),
            }
            match event {
                DuplexEvent::DownstreamRead(0) => {
                    log::info!("downstream session closing");
                    return;
                }
                DuplexEvent::UpstreamRead(0) => {
                    log::info!("upstream session closing");
                    return;
                }
                DuplexEvent::DownstreamRead(n) => {
                    log::info!("Forwarding {} bytes → upstream", n);
                    client_session.write_all(&upstream_buf[0..n]).await.unwrap();
                    client_session.flush().await.unwrap();
                }
                DuplexEvent::UpstreamRead(n) => {
                    log::info!("Forwarding {} bytes ← downstream", n);
                    server_session
                        .write_all(&downstream_buf[0..n])
                        .await
                        .unwrap();
                    server_session.flush().await.unwrap();
                }

            }
        }
    }
}

use std::net::{IpAddr, SocketAddr};
use std::mem;
use socket2::{Socket, SockAddr};
use std::mem::ManuallyDrop;
use std::os::unix::io::{AsRawFd, FromRawFd};

#[async_trait]
impl ServerApp for ProxyApp {
    async fn process_new(self: &Arc<Self>, io: Stream, _shutdown: &ShutdownWatch) -> Option<Stream> {
        let fd = if let Some(concrete) = io.as_any().downcast_ref::<L4Stream>() {
            Some(concrete.as_raw_fd())
        } else {
            log::info!("Failed to downcast to l4::stream::Stream");
            return None;
        };

        //was needed because the from raw fd was ending the connection
        let socket = ManuallyDrop::new(unsafe { Socket::from_raw_fd(fd.unwrap()) });

        let dst: SockAddr = match socket.original_dst() {
            Ok(addr) => addr,
            Err(e) => {
                log::info!("socket2::original_dst failed: {}", e);
                return None;
            }
        };

        let mut target = match dst.as_socket() {
            Some(addr) => addr,
            None => {
                log::info!("Failed to convert SockAddr to SocketAddr");
                return None;
            }
        };

        log::info!("original destination extracted via socket2 libraryr is : {}", target);

        let mut io = io;
        let mut peek_buf = [0u8; 8]; // enough for protocol detection

        let supported = io.try_peek(&mut peek_buf).await.unwrap_or(false);

        let mut is_tls = false;
        let mut is_http = false;
        if supported {
            log::info!("peeked bytes: {:02x?}", &peek_buf);

            is_tls = peek_buf.len() >= 3 && peek_buf[0] == 0x16 && peek_buf[1] == 0x03;
            is_http = peek_buf.len() >= 3 && (peek_buf.starts_with(b"GET") || peek_buf.starts_with(b"POS") || peek_buf.starts_with(b"HEA"));

            log::info!("prtcol detection tls: {}, http: {}", is_tls, is_http);
        } else {
            log::info!("peeking not supported on this stream");
        }
        if is_http || is_tls {
            let ip: IpAddr = "0.0.0.0".parse().unwrap();
            let port = if is_http { 7189 } else { 6189 };
            target = SocketAddr::new(ip, port);
            log::info!(
                "changing upstream based on protocol detection: {} → {}",
                if is_http { 
                    "http" 
                } else { 
                    "tls" 
                },
                target
            );
        }


        let peer = BasicPeer::new(&target.to_string());
        let client_session = self.client_connector.new_stream(&peer).await;
        log::info!("connected to upstream server: {}", target);
        log::info!("starting duplex between client and upstream");

        match client_session {
            Ok(client_session) => {
                self.duplex(io, client_session).await;
                None
            }
            Err(e) => {
                log::info!("failed to create client session: {}", e);
                None
            }
        }
    }
}