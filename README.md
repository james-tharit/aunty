# aunty

TUI that lists the hostnames your machine talks to (TLS SNI, plain-HTTP `Host`, DNS queries). Select one to see its IPs, ports and, for plain HTTP, the request headers, parameters and body.

```
sudo apt install libpcap-dev
cargo build --release
sudo ./target/release/aunty [interface]   # no interface: pick one in the TUI
```

Keys: mouse hover or ↑↓ select, `a` cycle app filter, space pause, q quit.

Limits: HTTPS is encrypted (hostname only); HTTP/3 (QUIC) is not parsed; app names come from `/proc` (Linux only, best effort; DNS shows the resolver).
