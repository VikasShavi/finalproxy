use crate::models::Certkey;
use dashmap::DashMap;
use once_cell::sync::Lazy;
use pingora_openssl::{ pkey::PKey, pkey::Private, x509::X509, x509::X509NameBuilder, nid::Nid, hash::MessageDigest, x509::extension::SubjectAlternativeName };

use openssl::{rsa::Rsa, bn::BigNum, asn1::{Asn1Time, Asn1Integer}, sha::sha256};
use std::{fs, fs::File, io::Write, path::Path};
fn generate_serial_number(domain: &str) -> Asn1Integer {
    let hash = sha256(domain.as_bytes());
    let bn = BigNum::from_slice(&hash[0..16]).unwrap();
    bn.to_asn1_integer().unwrap()
}

static CERT_CACHE: Lazy<DashMap<String, Certkey>> = Lazy::new(|| {
    let map = DashMap::new();
    load_cached_certs(&map);
    map
});

fn load_cached_certs(map: &DashMap<String, Certkey>) {
    if !Path::new("certs_cache").exists() {
        fs::create_dir_all("cert_cache").expect("Could not create cache dir");
        return;
    }

    for entry in fs::read_dir("certs_cache").unwrap() {
        if let Ok(entry) = entry {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) == Some("pem") {
                if let Some(file_stem) = path.file_stem().and_then(|s| s.to_str()) {
                    let key_path = Path::new("certs_cache").join(format!("{}.key", file_stem));
                    if key_path.exists() {
                        let cert_bytes = fs::read(&path).unwrap_or_default();
                        let key_bytes = fs::read(&key_path).unwrap_or_default();
                        if let (Ok(cert), Ok(key)) = (
                            X509::from_pem(&cert_bytes),
                            PKey::private_key_from_pem(&key_bytes),
                        ) {
                            map.insert(file_stem.to_string(), Certkey { cert, key });
                        }
                    }
                }
            }
        }
    }
}

static CA_CERT: Lazy<X509> = Lazy::new(|| {
    let pem = fs::read("keys/rootCA.pem").expect("Failed to read rootCA.pem");
    X509::from_pem(&pem).expect("Failed to parse root CA cert")
});

static CA_KEY: Lazy<PKey<Private>> = Lazy::new(|| {
    let pem = fs::read("keys/rootCA.key").expect("Failed to read rootCA.key");
    PKey::private_key_from_pem(&pem).expect("Failed to parse root CA key")
});

pub fn generate_fake_cert(domain: &str) -> Result<Certkey, String>{
    // let ca_cert_pem = fs::read("keys/rootCA.pem").map_err(|e| format!("Could not read rootCA.pem: {}", e))?;
    // let ca_key_pem = fs::read("keys/rootCA.key").map_err(|e| format!("Could not read rootCA.key: {}", e))?;
    //
    // let ca_cert = X509::from_pem(&ca_cert_pem).map_err(|e| format!("Could not parse CA cert: {}", e))?;
    // let ca_key = PKey::private_key_from_pem(&ca_key_pem).map_err(|e| format!("Could not parse CA key: {}", e))?;

    if let Some(cached_cert) = CERT_CACHE.get(domain) {
        return Ok(cached_cert.clone());
    }

    let ca_cert = CA_CERT.as_ref();
    let ca_key = CA_KEY.as_ref();

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
    // builder.set_serial_number(&BigNum::from_u32(&generate_serial_number(domain)).unwrap().to_asn1_integer().unwrap()).unwrap();
    builder.set_serial_number(&generate_serial_number(domain)).unwrap();
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

    fs::create_dir_all("certs_cache").ok();
    let cert_path = format!("certs_cache/{}.pem", domain);
    let key_path = format!("certs_cache/{}.key", domain);
    let mut cert_file = File::create(cert_path).map_err(|e| e.to_string())?;
    let mut key_file = File::create(key_path).map_err(|e| e.to_string())?;
    cert_file.write_all(&cert.to_pem().map_err(|e| e.to_string())?)
        .map_err(|e| e.to_string())?;
    key_file
        .write_all(&pkey.private_key_to_pem_pkcs8().map_err(|e| e.to_string())?)
        .map_err(|e| e.to_string())?;

    println!("created a fake cert for {}: {:?}", domain, cert);
    // CertKey::new(vec![cert], pkey)
    let res = Certkey {
        cert,
        key: pkey
    };
    CERT_CACHE.insert(domain.to_string(), res.clone());
    Ok(res)
}
