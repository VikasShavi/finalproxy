use std::collections::HashMap;
use serde::{Serialize, Deserialize};
use pingora_openssl::{ pkey::PKey, pkey::Private, x509::X509 };
use flate2::Decompress;

#[derive(serde::Serialize)]
#[serde(tag = "log_type")]
pub enum LogEvent {
    Http(HttpLog),
    WebSocket(WebSocketLog),
}

#[derive(Default, Serialize, Deserialize)]
pub struct WebSocketLog {
    pub timestamp: String,
    pub dir: String,
    pub ip: String, // from ctx.client_ip
    // pub uri: String,     // from ctx.uri
    pub msg: String,
}

#[derive(Default, Deserialize, Serialize)]
pub struct HttpLog {
    pub timestamp: String,

    pub client_ip: String,

    pub method: String,

    pub uri: String,

    pub upstream_server: String,

    pub request_headers: HashMap<String, String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_body: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_status: Option<u16>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_headers: Option<HashMap<String, String>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_body: Option<String>,
}

#[derive(Default)]
pub struct RequestResponseLogging {
    pub is_websocket: bool,
    pub websocket_upgrade_completed: bool,
    pub ctosdecompressor: Option<Decompress>,
    pub stocdecompressor: Option<Decompress>,
    pub deflating: bool,
    pub timestamp: String,
    pub client_ip: String,
    pub method: String,
    pub uri: String,
    pub upstream_server: String,
    pub request_headers: HashMap<String, String>,
    pub request_body: Option<String>,
    pub response_status: Option<u16>,
    pub response_headers: Option<HashMap<String, String>>,
    pub response_body: Option<String>,
}

#[derive(Clone)]
pub struct Certkey {
    pub cert: X509,
    pub key: PKey<Private>,
}