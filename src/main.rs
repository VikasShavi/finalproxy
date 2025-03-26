mod modules;
mod fakegencert;

use std::io::Write;
use async_trait::async_trait;
use bytes::Bytes;
use std::collections::HashMap;
use std::str;

use pingora_openssl::ssl::NameType;
use pingora_proxy::{http_proxy_service, ProxyHttp, Session};
use pingora_core::{modules::http::HttpModuleBuilder, server::Server, upstreams::peer::Peer, Result};
use pingora_core::upstreams::peer::{HttpPeer, PeerOptions};
use pingora_core::listeners::tls::TlsSettings;
use pingora_core::listeners::TlsAccept;
use pingora_core::listeners::TlsAcceptCallbacks;
use pingora_core::protocols::tls::TlsRef;
use pingora_http::RequestHeader;
use pingora_http::ResponseHeader;

use once_cell::sync::OnceCell;
use tokio::{ sync::mpsc::Sender, fs::OpenOptions, io::AsyncWriteExt };

static LOGGER: OnceCell<Sender<String>> = OnceCell::new();

struct MITM;

#[async_trait]
impl ProxyHttp for MITM {
    type CTX = modules::RequestResponseLogging;

    fn new_ctx(&self) -> Self::CTX {
        modules::RequestResponseLogging::default()
    }

    async fn upstream_peer(&self, session: &mut Session, _ctx: &mut Self::CTX) -> Result<Box<HttpPeer>> {
        let conn = session.get_header("Host").unwrap().to_str().unwrap();

        if session.server_addr().unwrap().to_string().contains("7189") {
            let mut peer = HttpPeer::new(format!("{}", conn), false, " ".to_string());
            Ok(Box::new(peer))
        }
        else{
            let sni = conn.split(':').next().unwrap();
            let port = conn.split(':').nth(1).unwrap_or("443").parse::<u16>().unwrap();
            let mut peer = HttpPeer::new(format!("{}:{}", conn, port), true, format!("{}", sni));
            // let mut toot = PeerOptions::new();
            // // toot.verify_cert = false;
            // peer.options = toot;

            Ok(Box::new(peer))
        }
    }

    async fn upstream_request_filter(&self, session: &mut Session, upstream_request: &mut RequestHeader, ctx: &mut Self::CTX) -> Result<()> {
        ctx.method = Some(upstream_request.method.to_string());
        ctx.uri = Some(upstream_request.uri.to_string());
        ctx.host = session.get_header("Host").map(|h| h.to_str().unwrap_or("").to_string());
        ctx.client_ip = session.client_addr().map(|ip| ip.to_string());

        let mut headers = HashMap::new();
        for (keys, values) in upstream_request.headers.iter() {
            if let Ok(v) = values.to_str() {
                headers.insert(keys.to_string(), v.to_string());
            }
        }
        ctx.request_headers = Some(headers);
        upstream_request.append_header("x-added-by-proxy", "secret-token")?;
        Ok(())
    }

    async fn response_filter(&self, _session: &mut Session, upstream_response: &mut ResponseHeader, ctx: &mut Self::CTX) -> Result<()> {
        ctx.response_status = Some(upstream_response.status.as_u16());
        let mut headers = HashMap::new();
        for (keys, values) in upstream_response.headers.iter() {
            if let Ok(v) = values.to_str() {
                headers.insert(keys.to_string(), v.to_string());
            }
        }
        ctx.response_headers = Some(headers);


        let status = upstream_response.status;
        let content_type = upstream_response
            .headers
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("unknown");

        println!("logging Status: {}, Content-Type: {}", status, content_type);

        Ok(())
    }


    fn upstream_response_body_filter(&self, _session: &mut Session, body: &mut Option<Bytes>, end_of_stream: bool, ctx: &mut Self::CTX) {
        if let Some(data) = body {
            let is_gzip = match &ctx.response_headers {
                Some(headers) => headers.get("content-encoding").map_or(false, |value| value == "gzip"),
                None => false,
            };
            if is_gzip {
                ctx.response_body.push_str("GZIP compressed body");
            } else if let Ok(body) = str::from_utf8(data) {
                println!("body: {}", body);
                ctx.response_body.push_str(body);
            } else {
                println!("non ascii body: {:?}", data);
                ctx.response_body.push_str(&format!("{:?}", data));
            }
        }

        if end_of_stream {
            if let Ok(json) = serde_json::to_string_pretty(ctx) {
                println!("{}", json);
                if let Some(sender) = LOGGER.get() {
                    sender.try_send(json); // non-blocking
                }
            }
            println!("end of body");
        }
    }
}

struct MyTlsHandler;

#[async_trait::async_trait]
impl TlsAccept for MyTlsHandler {
    async fn certificate_callback(&self, ssl: &mut TlsRef) {
        if let Some(sni) = ssl.servername(NameType::HOST_NAME) {
            println!("SNI received is: {}", sni);

            match fakegencert::generate_fake_cert(sni) {
                Ok(certkey) => {
                    if let Err(e) = ssl.set_certificate(&certkey.cert) {
                        println!("error in setting certificate: {}", e);
                        return;
                    }

                    if let Err(e) = ssl.set_private_key(&certkey.key) {
                        println!("error in setting private key: {}", e);
                        return;
                    }
                }
                Err(e) => {
                    println!("error generating fake cert for '{}': {}", sni, e);
                }
            }
        }
    }
}

use tokio::runtime::Runtime;
fn main() {
    let rt = Runtime::new().unwrap();

    rt.spawn(async {
        let (tx, mut rx) = tokio::sync::mpsc::channel::<String>(1000);
        LOGGER.set(tx).unwrap();

        let log_file_path = "/tmp/proxylog.json";
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(log_file_path)
            .await
            .expect("cannot open file");

        while let Some(entry) = rx.recv().await {
            if let Err(e) = file.write_all(entry.as_bytes()).await {
                println!("error writing request: {}", e);
            }
            let _ = file.write_all(b"\n").await;
        }
    });


    let mut server = Server::new(None).unwrap();
    server.bootstrap();

    let my_tls_handler = MyTlsHandler;

    let tls_callbacks: TlsAcceptCallbacks = Box::new(my_tls_handler);

    let tls_settings = TlsSettings::with_callbacks(tls_callbacks).unwrap();
    let mut proxy = http_proxy_service(&server.configuration, MITM);
    proxy.add_tls_with_settings("0.0.0.0:6189", None, tls_settings);

    proxy.add_tcp("0.0.0.0:7189");
    server.add_service(proxy);
    println!("https Proxy listening on 0.0.0.0:6189");
    println!("http proxy listening on 0.0.0.0:7189");
    server.run_forever();
}
