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

## Compile the code
```bash
cargo build --features server --bin server --release
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
sudo chown mitm:mitm keys/rootCA.*
sudo -u mitm target/release/server
```

## Example output of log files

#### Http Log
```json
{
  "log_type": "Http",
  "is_websocket": false,
  "websocket_upgrade_completed": false,
  "deflating": false,
  "timestamp": "Sat, 29 Mar 2025 18:12:24 GMT",
  "client_ip": "127.0.0.1:50559",
  "method": "GET",
  "uri": "/keys/",
  "upstream_server": "test.com:7189",
  "request_headers": {
    "user-agent": "curl/8.7.1",
    "host": "test.com:7189",
    "accept": "*/*"
  },
  "response_status": 200,
  "response_headers": {
    "content-length": "277",
    "date": "Sat, 29 Mar 2025 18:12:24 GMT",
    "content-type": "text/html; charset=utf-8",
    "server": "SimpleHTTP/0.6 Python/3.12.2"
  },
  "response_body": "<!DOCTYPE HTML>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n<title>Directory listing for /keys/</title>\n</head>\n<body>\n<h1>Directory listing for /keys/</h1>\n<hr>\n<ul>\n<li><a href=\"cert.pem\">cert.pem</a></li>\n<li><a href=\"key.pem\">key.pem</a></li>\n</ul>\n<hr>\n</body>\n</html>\n"
}
{
  "log_type": "Http",
  "is_websocket": true,
  "websocket_upgrade_completed": false,
  "deflating": true,
  "timestamp": "Sat, 29 Mar 2025 18:12:37 GMT",
  "client_ip": "127.0.0.1:50561",
  "method": "GET",
  "uri": "/",
  "upstream_server": "127.0.0.1:7189",
  "request_headers": {
    "sec-websocket-version": "13",
    "sec-websocket-extensions": "permessage-deflate; client_max_window_bits",
    "upgrade": "websocket",
    "host": "127.0.0.1:7189",
    "sec-websocket-key": "kXkG+CsKM6ObMbTSoh8l8g==",
    "connection": "Upgrade"
  },
  "response_status": 101,
  "response_headers": {
    "sec-websocket-accept": "rz9mBtWYfTHucGYdfNf1LBqVScY=",
    "date": "Sat, 29 Mar 2025 18:12:37 GMT",
    "server": "Python/3.12 websockets/13.1",
    "upgrade": "websocket",
    "connection": "Upgrade",
    "sec-websocket-extensions": "permessage-deflate; server_max_window_bits=12; client_max_window_bits=12"
  }
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
