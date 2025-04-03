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
iptables -t nat -A OUTPUT -p tcp --dport 0:65535 -m owner ! --uid-owner mitm -j REDIRECT --to-ports 8189
```

## Generating own keys (valid for 1 year)
```bash
mkdir keys certs_cache
openssl genrsa -out keys/rootCA.key 2048
openssl req -x509 -new -nodes -key keys/rootCA.key -sha256 -days 365 -out keys/rootCA.pem
```

## Running the code
```bash
sudo chown -R mitm:mitm keys/rootCA.* certs_cache
sudo -u mitm target/release/server
```

## Example output of log files

#### Http Log
```json
{
  "log_type": "Http",
  "timestamp": "Thu, 03 Apr 2025 09:55:29 GMT",
  "client_ip": "127.0.0.1:57656",
  "method": "GET",
  "uri": "/temp.jpeg",
  "upstream_server": "test.com:4444",
  "request_headers": {
    "user-agent": "curl/8.13.0-rc2",
    "host": "test.com:4444",
    "accept": "*/*"
  },
  "response_status": 200,
  "response_headers": {
    "date": "Thu, 03 Apr 2025 09:55:29 GMT",
    "content-length": "671720",
    "server": "SimpleHTTP/0.6 Python/3.11.9",
    "last-modified": "Thu, 03 Apr 2025 09:53:34 GMT",
    "content-type": "image/jpeg"
  },
  "response_body": "not logged because it is image/jpeg file"
}
{
  "log_type": "Http",
  "timestamp": "Thu, 03 Apr 2025 09:56:41 GMT",
  "client_ip": "127.0.0.1:50464",
  "method": "GET",
  "uri": "/g/chains/202402/remote-settings.content-signature.mozilla.org-2025-04-21-18-01-52.chain",
  "upstream_server": "content-signature-2.cdn.mozilla.net",
  "request_headers": {
    "accept": "*/*",
    "host": "content-signature-2.cdn.mozilla.net",
    "accept-encoding": "gzip, deflate, br",
    "user-agent": "Mozilla/5.0 (X11; Linux aarch64; rv:109.0) Gecko/20100101 Firefox/115.0",
    "connection": "keep-alive",
    "accept-language": "en-US,en;q=0.5"
  },
  "response_status": 200,
  "response_headers": {
    "date": "Thu, 03 Apr 2025 09:52:07 GMT",
    "content-disposition": "attachment",
    "age": "274",
    "x-amz-request-id": "6SMGFCD5FZHBFGSG",
    "last-modified": "Sun, 02 Mar 2025 18:01:53 GMT",
    "x-amz-server-side-encryption": "AES256",
    "server": "AmazonS3",
    "accept-ranges": "bytes",
    "x-amz-id-2": "ohatpT6e56qK0oS8zVb5f2....aQRRM7c9xYfOEJsFmMdw==",
    "content-type": "binary/octet-stream",
    "cache-control": "public,max-age=3600",
    "content-length": "5307",
    "alt-svc": "clear",
    "via": "1.1 google",
    "etag": "\"caaafd2e.....4a0af2cf3\""
  },
  "response_body": "-----BEGIN CERTIFICATE-----\nMIIC9DCCAnmgAw....SNIP....igKgdH78qM\nHpdXrbaTDFsfMLTAMnGFnqOZMuMobNJS5M6/vqdepoC8L7xmI5dQgW8YGyymr8DP\ngchMof0tylgn\n-----END CERTIFICATE-----\n"
}
```

#### Websocket Log
```json
{
  "log_type": "WebSocket",
  "timestamp": "2025-04-03T09:56:41.529556471+00:00",
  "dir": "ctos",
  "from_ip": "127.0.0.1:50474",
  "uri": "/",
  "websocket_session_id": "1d925951-5fe7-4aff-a296-14dd5f0bbde0",
  "msg": "{\"messageType\":\"hello\",\"broadcasts\":{\"remote-settings/monitor_changes\":\"\\\"1743649028895\\\"\"},\"use_webpush\":true}"
}
{
  "log_type": "WebSocket",
  "timestamp": "2025-04-03T09:59:24.806392352+00:00",
  "dir": "ctos",
  "from_ip": "127.0.0.1:35260",
  "uri": "/",
  "websocket_session_id": "76c7239a-e262-47d9-b910-ed2c9d3f40eb",
  "msg": "pwd"
}
{
  "log_type": "WebSocket",
  "timestamp": "2025-04-03T09:59:26.971051892+00:00",
  "dir": "ctos",
  "from_ip": "127.0.0.1:35260",
  "uri": "/",
  "websocket_session_id": "76c7239a-e262-47d9-b910-ed2c9d3f40eb",
  "msg": "ls -la"
}
```
