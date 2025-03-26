use std::{fs, str};
use openssl::{ rsa::Rsa, bn::BigNum, asn1::Asn1Time };
use std::time::{SystemTime, UNIX_EPOCH};
use crate::modules::Certkey;
use dashmap::DashMap;
use once_cell::sync::Lazy;
use pingora_openssl::{ pkey::PKey, x509::X509, x509::X509NameBuilder, nid::Nid, hash::MessageDigest, x509::extension::SubjectAlternativeName };

fn generate_serial_number() -> u32 {
    let timestamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    timestamp as u32
}

static CERT_CACHE: Lazy<DashMap<String, Certkey>> = Lazy::new(DashMap::new);

pub fn generate_fake_cert(domain: &str) -> Result<Certkey, String>{
    let ca_cert_pem = fs::read("keys/rootCA.pem").map_err(|e| format!("Could not read rootCA.pem: {}", e))?;
    let ca_key_pem = fs::read("keys/rootCA.key").map_err(|e| format!("Could not read rootCA.key: {}", e))?;

    let ca_cert = X509::from_pem(&ca_cert_pem).map_err(|e| format!("Could not parse CA cert: {}", e))?;
    let ca_key = PKey::private_key_from_pem(&ca_key_pem).map_err(|e| format!("Could not parse CA key: {}", e))?;

    if let Some(cached_cert) = CERT_CACHE.get(domain) {
        return Ok(cached_cert.clone());
    }

    let rsa = Rsa::generate(2048).unwrap();
    let pkey = PKey::from_rsa(rsa).unwrap();

    let mut name = X509NameBuilder::new().unwrap();

    let max_len = 64;
    let mut t = domain;
    if domain.len() > max_len {
        t = &domain[0..max_len]
    };
    name.append_entry_by_nid(Nid::COMMONNAME, t).map_err(|e| format!("Could not create fake cert, nid error: {}", e))?;
    let name = name.build();

    let mut builder = X509::builder().unwrap();
    builder.set_serial_number(&BigNum::from_u32(generate_serial_number()).unwrap().to_asn1_integer().unwrap()).unwrap();
    builder.set_version(2).unwrap();
    builder.set_subject_name(&name).unwrap();
    builder.set_issuer_name(ca_cert.subject_name()).unwrap();
    builder.set_pubkey(&pkey).unwrap();
    builder.set_not_before(&Asn1Time::days_from_now(0).unwrap()).unwrap();
    builder.set_not_after(&Asn1Time::days_from_now(365).unwrap()).unwrap();

    // // SAN (Subject Alt Name)
    let mut san = SubjectAlternativeName::new();
    san.dns(domain);
    let san_ext = san.build(&builder.x509v3_context(Some(&ca_cert), None)).unwrap();
    builder.append_extension(san_ext).map_err(|e| format!("Could not create fake cert, san error: {}", e))?;

    builder.sign(&ca_key, MessageDigest::sha256()).map_err(|e| format!("Could not sign fake cert: {}", e))?;
    let cert = builder.build();

    println!("ccreated a fake cert for reddit; {:?}", cert);
    // CertKey::new(vec![cert], pkey)
    let res = Certkey {
        cert,
        key: pkey
    };
    CERT_CACHE.insert(domain.to_string(), res.clone());
    Ok(res)
}
