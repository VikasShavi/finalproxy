use std::collections::HashMap;
use serde::{Serialize, Deserialize};
use pingora_openssl::{ pkey::PKey, pkey::Private, x509::X509 };
#[derive(Default, Deserialize, Serialize)]
pub struct RequestResponseLogging {
    pub client_ip: Option<String>,
    pub method: Option<String>,
    pub uri: Option<String>,
    pub host: Option<String>,
    pub request_headers: Option<HashMap<String, String>>,
    pub request_body: String,
    pub response_status: Option<u16>,
    pub response_headers: Option<HashMap<String, String>>,
    pub response_body: String,
}

#[derive(Clone)]
pub struct Certkey {
    pub cert: X509,
    pub key: PKey<Private>,
}