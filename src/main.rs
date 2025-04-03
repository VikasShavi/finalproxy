use flate2::Decompress;
use uuid::Uuid;

use pingora_proxy::{http_proxy_service, ProxyHttp, Session};
use pingora_core::upstreams::peer::{ HttpPeer, PeerOptions };
use pingora_core::listeners::tls::TlsSettings;
use pingora_core::listeners::TlsAccept;
use pingora_core::listeners::TlsAcceptCallbacks;
use pingora_core::protocols::tls::TlsRef;
use pingora_openssl::ssl::NameType;
use async_trait::async_trait;
use pingora_core::server::Server;
use pingora_core::Result;
use bytes::Bytes;
use pingora_http::{ ResponseHeader, RequestHeader };

use std::str;
use std::collections::HashMap;
use env_logger;

mod models;
use models::RequestResponseLogging;
use models::WebSocketLog;
use models::LogEvent;
use models::HttpLog;

mod stocdecoder;
use stocdecoder::decode_server_ws_frame;

mod ctosdecoder;
use ctosdecoder::decode_client_ws_frame;

mod fakegencert;
use fakegencert::generate_fake_cert;

mod tcpproxy;
use tcpproxy::proxy_service;

struct MITM;

#[async_trait]
impl ProxyHttp for MITM {
    type CTX = RequestResponseLogging;

    fn new_ctx(&self) -> Self::CTX {
        RequestResponseLogging::default()
    }

    async fn upstream_peer(&self, session: &mut Session, _ctx: &mut Self::CTX) -> Result<Box<HttpPeer>> {
        let conn = session.get_header("Host").unwrap().to_str().unwrap();
        let sni = conn.split(':').next().unwrap();

        if session.server_addr().unwrap().to_string().contains("7189") {
            let port = conn.split(':').nth(1).unwrap_or("80").parse::<u16>().unwrap();
            let mut peer = HttpPeer::new(format!("{}:{}", sni, port), false, "".to_string());
            Ok(Box::new(peer))
        } else {
            let port = conn.split(':').nth(1).unwrap_or("443").parse::<u16>().unwrap();
            let mut peer = HttpPeer::new(format!("{}:{}", sni, port), true, format!("{}", sni));
            let mut toot = PeerOptions::new();
            toot.verify_cert = false;
            peer.options = toot;

            Ok(Box::new(peer))
        }
    }
    async fn upstream_request_filter(&self, session: &mut Session, upstream_request: &mut RequestHeader, ctx: &mut Self::CTX) -> Result<()> {
        // log::info!("upstream_request filter");
        if !ctx.is_websocket {
            ctx.method = upstream_request.method.to_string();
            ctx.uri = upstream_request.uri.to_string();
            let mut headers = HashMap::new();
            for (keys, values) in upstream_request.headers.iter() {
                if let Ok(v) = values.to_str() {
                    headers.insert(keys.to_string(), v.to_string());
                }
            }
            ctx.request_headers = headers;
        }
        ctx.upstream_server = session.get_header("Host").map(|h| h.to_str().unwrap_or("").to_string()).unwrap();
        ctx.client_ip = session.client_addr().map(|ip| ip.to_string()).unwrap();
        ctx.timestamp = chrono::Utc::now().format("%a, %d %b %Y %H:%M:%S GMT").to_string();


        // Can add custom headers to send to upstream server
        upstream_request.append_header("x-added-by-proxy", "secret-token")?;
        Ok(())
    }
    async fn response_filter(&self, _session: &mut Session, upstream_response: &mut ResponseHeader, ctx: &mut Self::CTX) -> Result<()> {
        // log::info!("response_filter");
        if let Some(header) = upstream_response.headers.get("upgrade") {
            if header == "websocket" {
                let mut windowbits: u8 = 12;
                if let Some(headertwo) = upstream_response.headers.get("sec-websocket-extensions") {
                    match headertwo.to_str() {
                        Ok(s) => {
                            for part in s.split(';') {
                                let temp = part.trim();
                                if temp.starts_with("server_max_window_bits=") {
                                    if let Some(value) = temp.split("=").nth(1) {
                                        windowbits = value.parse::<u8>().unwrap_or(12);
                                    }
                                }
                                if temp.contains("deflate") {
                                    ctx.deflating = true;
                                }
                            }
                        }
                        Err(_) => {}
                    }
                }
                ctx.is_websocket = true;
                ctx.websocket_upgrade_completed = false;
                ctx.websocket_session_id = Uuid::new_v4().to_string();
                ctx.stocdecompressor = Some(Decompress::new_with_window_bits(false, windowbits));
                ctx.ctosdecompressor = Some(Decompress::new_with_window_bits(false, windowbits));
            }
        }

        // logging the response headers
        ctx.response_status = Some(upstream_response.status.as_u16());
        let mut headers = HashMap::new();
        for (keys, values) in upstream_response.headers.iter() {
            if let Ok(v) = values.to_str() {
                headers.insert(keys.to_string(), v.to_string());
            }
        }
        ctx.response_headers = Some(headers);
        if ctx.is_websocket && !ctx.websocket_upgrade_completed {
            let http_log = HttpLog {
                timestamp: ctx.timestamp.clone(),
                client_ip: ctx.client_ip.clone(),
                method: ctx.method.clone(),
                uri: ctx.uri.clone(),
                upstream_server: ctx.upstream_server.clone(),
                request_headers: ctx.request_headers.clone(),
                request_body: None,
                response_status: ctx.response_status.clone(),
                response_headers: ctx.response_headers.clone(),
                response_body: ctx.response_body.clone(),
            };
            if let Some(sender) = LOGGER.get() {
                let _ = sender.try_send(LogEvent::Http(http_log));
            }
            ctx.websocket_upgrade_completed = true;
        }
        Ok(())
    }

    async fn request_body_filter(&self, _session: &mut Session, body: &mut Option<Bytes>, end_of_stream: bool, ctx: &mut Self::CTX) -> Result<()> {
        // log::info!("request_body_filter");
        if let Some(data) = body {
            if ctx.is_websocket {
                // ctx.clear_http_fields();
                if let Some(ref mut decompressor) = ctx.ctosdecompressor {
                    if let Some(decoded) = decode_client_ws_frame(decompressor, data, ctx.deflating) {
                        log::info!("Decoded message from client to server websocket is {}", decoded);
                        if decoded != String::new() {
                            let ws_log = WebSocketLog {
                                timestamp: chrono::Utc::now().to_rfc3339(),
                                dir: "ctos".into(), // or "stoc"
                                from_ip: ctx.client_ip.clone(),
                                uri: ctx.uri.clone(),
                                websocket_session_id: ctx.websocket_session_id.clone(),
                                msg: decoded,
                            };
                            if let Some(sender) = LOGGER.get() {
                                let _ = sender.try_send(LogEvent::WebSocket(ws_log)); // non-blocking
                            }
                        }
                    }
                    else {
                        log::warn!("failed to decode");
                    }
                }
                else {
                    log::warn!("cannot init a decompressor");
                }
            }
            else {
                if let Ok(readbody) = str::from_utf8(data) {
                    let snippet = readbody.get(..50).unwrap_or(readbody);
                    log::info!("body: \n{}", snippet);
                    ctx.request_body.get_or_insert_with(String::new).push_str(readbody);
                } else {
                    let snippet = data.get(..100).unwrap_or(data);
                    // log::info!("body: \n{:?}", snippet);
                    ctx.request_body.get_or_insert_with(String::new).push_str(&format!("{:?}", data));
                }

                if end_of_stream {
                    log::info!("end of request body");
                }
            }
        }
        Ok(())
    }


    fn upstream_response_body_filter(&self, _session: &mut Session, body: &mut Option<Bytes>, end_of_stream: bool, ctx: &mut Self::CTX) {
        // Check if there's a Content-Type header in the response headers.
        if let Some(ref headers) = ctx.response_headers {
            if let Some(content_type) = headers.get("content-type") {
                if is_media_content(content_type) {
                    log::info!("not logged because it is {} file", content_type);
                    if end_of_stream {
                        let http_log = HttpLog {
                            timestamp: ctx.timestamp.clone(),
                            client_ip: ctx.client_ip.clone(),
                            method: ctx.method.clone(),
                            uri: ctx.uri.clone(),
                            upstream_server: ctx.upstream_server.clone(),
                            request_headers: ctx.request_headers.clone(),
                            request_body: ctx.request_body.clone(),
                            response_status: ctx.response_status.clone(),
                            response_headers: ctx.response_headers.clone(),
                            response_body: Some(format!("not logged because it is {} file", content_type)),
                        };
                        if let Some(sender) = LOGGER.get() {
                            let _ = sender.try_send(LogEvent::Http(http_log));
                        }
                        log::info!("end of response body");
                    }
                    return;
                }
            }
        }
        if let Some(data) = body {
            if ctx.is_websocket {
                // ctx.clear_http_fields();
                if let Some(ref mut decompressor) = ctx.stocdecompressor {
                    if let Some(decoded) = decode_server_ws_frame(decompressor, &data, ctx.deflating) {
                        log::info!("decoded message from server to client websocket is {}", decoded);
                        if decoded != String::new() {
                            let ws_log = WebSocketLog {
                                timestamp: chrono::Utc::now().to_rfc3339(),
                                dir: "stoc".into(), // or "stoc"
                                from_ip: ctx.upstream_server.clone(),
                                uri: ctx.uri.clone(),
                                msg: decoded,
                                websocket_session_id: ctx.websocket_session_id.clone(),
                            };
                            if let Some(sender) = LOGGER.get() {
                                let _ = sender.try_send(LogEvent::WebSocket(ws_log));
                            }
                        }
                    }
                    else {
                        log::warn!("failed to decode");
                    }
                }
                else {
                    log::warn!("cannot init a decompressor");
                }
            }
            else {
                if let Ok(readbody) = str::from_utf8(data) {
                    let snippet = readbody.get(..50).unwrap_or(readbody);
                    log::info!("body: \n{}", snippet);
                    ctx.response_body.get_or_insert_with(String::new).push_str(readbody);
                } else {
                    let snippet = data.get(..50).unwrap_or(data);
                    // log::info!("body: \n{:?}", snippet);
                    ctx.response_body.get_or_insert_with(String::new).push_str(&format!("{:?}", data));
                }

                if end_of_stream {
                    let http_log = HttpLog {
                        timestamp: ctx.timestamp.clone(),
                        client_ip: ctx.client_ip.clone(),
                        method: ctx.method.clone(),
                        uri: ctx.uri.clone(),
                        upstream_server: ctx.upstream_server.clone(),
                        request_headers: ctx.request_headers.clone(),
                        request_body: ctx.request_body.clone(),
                        response_status: ctx.response_status.clone(),
                        response_headers: ctx.response_headers.clone(),
                        response_body: ctx.response_body.clone(),
                    };
                    if let Some(sender) = LOGGER.get() {
                        let _ = sender.try_send(LogEvent::Http(http_log)); // non-blocking
                    }
                    log::info!("end of response body");
                }
            }
        }
    }
}

fn is_media_content(content_type: &str) -> bool {
    let ct = content_type.to_lowercase();
    ct.starts_with("image/") || ct.starts_with("video/") || ct.starts_with("audio/") || ct.contains("font") || ct.contains("css")
}

struct MyTlsHandler;

#[async_trait]
impl TlsAccept for MyTlsHandler {
    async fn certificate_callback(&self, ssl: &mut TlsRef) {
        if let Some(sni) = ssl.servername(NameType::HOST_NAME) {
            log::info!("SNI received is: {}", sni);

            match generate_fake_cert(sni) {
                Ok(certkey) => {
                    if let Err(e) = ssl.set_certificate(&certkey.cert) {
                        log::warn!("error in setting certificate: {}", e);
                        return;
                    }

                    if let Err(e) = ssl.set_private_key(&certkey.key) {
                        log::warn!("error in setting private key: {}", e);
                        return;
                    }
                }
                Err(e) => {
                    log::warn!("error generating fake cert for '{}': {}", sni, e);
                }
            }
        }
    }
}




use tokio::runtime::Runtime;
use once_cell::sync::OnceCell;
use tokio::{sync::mpsc::Sender, fs::OpenOptions, io::AsyncWriteExt };

static LOGGER: OnceCell<Sender<LogEvent>> = OnceCell::new();


fn main() {
    env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));
    let rt = Runtime::new().unwrap();

    rt.spawn(async {
        let (tx, mut rx) = tokio::sync::mpsc::channel::<LogEvent>(1000);
        LOGGER.set(tx).unwrap();

        let mut http_file = OpenOptions::new()
            .create(true)
            .append(true)
            .open("/tmp/httplog.json")
            .await
            .expect("cannot open file");

        let mut ws_file = OpenOptions::new()
            .create(true)
            .append(true)
            .open("/tmp/wslog.json")
            .await
            .expect("cannot open file");

        while let Some(log) = rx.recv().await {
            match log {
                LogEvent::Http(http_log) => {
                    if let Ok(json) = serde_json::to_string_pretty(&LogEvent::Http(http_log)) {
                        let _ = http_file.write_all(json.as_bytes()).await;
                        let _ = http_file.write_all(b"\n").await;
                    }
                }
                LogEvent::WebSocket(ws_log) => {
                    if let Ok(json) = serde_json::to_string_pretty(&LogEvent::WebSocket(ws_log)) {
                        let _ = ws_file.write_all(json.as_bytes()).await;
                        let _ = ws_file.write_all(b"\n").await;
                    }
                }
            }
        }
    });

    let mut server = Server::new(None).unwrap();
    server.bootstrap();

    let my_tls_handler = MyTlsHandler;

    let tls_callbacks: TlsAcceptCallbacks = Box::new(my_tls_handler);

    let tls_settings = TlsSettings::with_callbacks(tls_callbacks).unwrap();
    let mut proxyhttps = http_proxy_service(&server.configuration, MITM);
    proxyhttps.add_tls_with_settings("0.0.0.0:6189", None, tls_settings);

    let mut proxyhttp = http_proxy_service(&server.configuration, MITM);
    proxyhttp.add_tcp("0.0.0.0:7189");

    let tcp_proxy = proxy_service("0.0.0.0:8189");

    server.add_services(vec![Box::new(proxyhttp), Box::new(proxyhttps), Box::new(tcp_proxy)]);
    log::info!("https Proxy listening on 0.0.0.0:6189");
    log::info!("http proxy listening on 0.0.0.0:7189");
    log::info!("tcp Proxy listening on 0.0.0.0:8189");

    server.run_forever();
}