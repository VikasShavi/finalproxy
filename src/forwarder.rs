use tokio::net::{TcpListener, TcpStream};
use tokio::io::copy_bidirectional;
use std::net::SocketAddr;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let listener = TcpListener::bind("0.0.0.0:9000").await?;
    println!("forwarder listening on 0.0.0.0:9000");

    loop {
        let (client, addr) = listener.accept().await?;
        tokio::spawn(async move {
            if let Err(e) = handle_connection(client, addr).await {
                println!("Error from {}: {:?}", addr, e);
            }
        });
    }
}

async fn handle_connection(mut client: TcpStream, addr: SocketAddr) -> anyhow::Result<()> {
    let mut bytestore = [0u8; 3];
    let nobytespeeked = client.peek(&mut bytestore).await?;

    let istls = nobytespeeked >= 3 && bytestore[0] == 0x16 && bytestore[1] == 0x03;
    let ishttp = nobytespeeked >= 3 && (bytestore.starts_with(b"GET") || bytestore.starts_with(b"POS") || bytestore.starts_with(b"HEA"));
    let proxyreq = istls || ishttp;
    match proxyreq {
        true => {
            if istls {
                println!("https {}, forwarding to 0.0.0.0:6189", addr);
                let mut server = TcpStream::connect("0.0.0.0:6189").await?;
                copy_bidirectional(&mut client, &mut server).await?;
            }
            else {
                println!("http {}, forwarding to 0.0.0.0:7189", addr);
                let mut server = TcpStream::connect("0.0.0.0:7189").await?;
                copy_bidirectional(&mut client, &mut server).await?;
            }
        }
        _ => {
            println!("not http/https at {}", addr);
        }
    }

    Ok(())
}