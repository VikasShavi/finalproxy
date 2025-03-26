# How to Run

## Files setup
```bash
git clone https://github.com/VikasShavi/finalproxy.git
cd finalproxy
git clone --branch 0.4.0 --depth 1 https://github.com/cloudflare/pingora.git
```

## Routing setup
```bash
sudo useradd --system --no-create-home mitm
sudo su -
echo 1 > /proc/sys/net/ipv4/ip_forward
iptables -t nat -A OUTPUT -p tcp --dport 443 -m owner ! --uid-owner mitm -j REDIRECT --to-ports 6189
iptables -t nat -A OUTPUT -p tcp --dport 80 -m owner ! --uid-owner mitm -j REDIRECT --to-ports 7189
```

## Running the code
```bash
cargo build --features server --bin server --release
sudo chown mitm:mitm keys/rootCA.*
sudo -u mitm target/release/server
```


## Optional - Generating own keys (valid for 1 year)
```bash
openssl genrsa -out rootCA.key 2048
openssl req -x509 -new -nodes -key rootCA.key -sha256 -days 365 -out rootCA.pem
```