# How to Run

## Files setup
```bash
git clone https://github.com/VikasShavi/finalproxy.git
cd finalproxy
git clone --branch 0.4.0 --depth 1 https://github.com/cloudflare/pingora.git
```

## Dependency issue fix for sfv crate
```bash
# Modify pingora-core's Cargo.toml
# Before
sfv = "0"

# After
sfv = "0.10.4"
```

## Routing setup
```bash
sudo useradd --system --no-create-home mitm
sudo su -
echo 1 > /proc/sys/net/ipv4/ip_forward
iptables -t nat -A OUTPUT -p tcp --dport 443 -m owner ! --uid-owner mitm -j REDIRECT --to-ports 6189
iptables -t nat -A OUTPUT -p tcp --dport 80 -m owner ! --uid-owner mitm -j REDIRECT --to-ports 7189
```

## Generating own keys (valid for 1 year)
```bash
mkdir keys
openssl genrsa -out keys/rootCA.key 2048
openssl req -x509 -new -nodes -key keys/rootCA.key -sha256 -days 365 -out keys/rootCA.pem
```

## Running the code
```bash
cargo build --features server --bin server --release
sudo chown mitm:mitm keys/rootCA.*
sudo -u mitm target/release/server
```

## Example output of log files

#### Http Log
```json
{
  "client_ip": "192.168.1.25:53752",
  "method": "POST",
  "uri": "/submit",
  "host": "hello.com",
  "request_headers": {
    "upgrade-insecure-requests": "1",
    "accept-language": "en-US,en;q=0.5",
    "sec-fetch-mode": "navigate",
    "origin": "https://hello.com",
    "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "accept-encoding": "gzip, deflate, br",
    "user-agent": "Mozilla/5.0 (X11; Linux aarch64; rv:109.0) Gecko/20100101 Firefox/115.0",
    "sec-fetch-user": "?1",
    "host": "hello.com",
    "connection": "keep-alive",
    "sec-fetch-site": "same-origin",
    "content-type": "application/x-www-form-urlencoded",
    "sec-fetch-dest": "document",
    "cookie": "_ga=GA1.2.2035304928.1743002572; _gid=GA1.2.599558051.1743002572; _gat=1; _gali=main",
    "content-length": "16",
    "referer": "https://hello.com/"
  },
  "request_body": "e=v%40v.com&l=en",
  "response_status": 200,
  "response_headers": {
    "x-cloud-trace-context": "7ac9a9855de096bbfacbdfb5713a176c",
    "vary": "Accept-Encoding",
    "date": "Wed, 26 Mar 2025 15:23:01 GMT",
    "transfer-encoding": "chunked",
    "content-encoding": "gzip",
    "server": "Google Frontend",
    "content-type": "text/html; charset=utf-8",
    "cache-control": "no-cache"
  },
  "response_body": "GZIP compressed body"
}
```

#### Websocket Log
```json
{
  "log_type": "WebSocket",
  "timestamp": "2025-03-30T07:32:52.506522981+00:00",
  "dir": "ctos",
  "ip": "127.0.0.1:35830",
  "msg": "pwd"
}
{
  "log_type": "WebSocket",
  "timestamp": "2025-03-30T07:32:53.413686213+00:00",
  "dir": "ctos",
  "ip": "127.0.0.1:35830",
  "msg": "sdkjjsdbh"
}
{
  "log_type": "WebSocket",
  "timestamp": "2025-03-30T07:32:54.203569803+00:00",
  "dir": "ctos",
  "ip": "127.0.0.1:35830",
  "msg": "dvfdv"
}
{
  "log_type": "WebSocket",
  "timestamp": "2025-03-30T07:32:57.075556141+00:00",
  "dir": "ctos",
  "ip": "127.0.0.1:35830",
  "msg": "dfvdfbfg shdfbjv8734838"
}
```