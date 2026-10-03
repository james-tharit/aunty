# aunty

TUI that lists the hostnames your machine talks to, with IPs, ports, owning app, and request URLs/headers/parameters/body.

```
sudo apt install libpcap-dev
cargo build --release
sudo ./target/release/aunty [interface]   # sniff: hostnames only (HTTPS is encrypted); no interface = pick in TUI
./target/release/aunty --mitm             # proxy: full HTTPS URLs/headers/body, no root
```

MITM mode listens on `127.0.0.1:8080`. On start it shows a launch command (Firefox by default, Tab for Chrome; Enter copies it). Firefox uses a throwaway profile in `~/.config/aunty/firefox` and must trust the CA in `~/.config/aunty/ca.pem` once: automatic if `certutil` is installed (`apt install libnss3-tools`), else import it in Settings > Certificates > Authorities. Never point your real profile at it.

Keys: mouse hover or ↑↓ select, `a` cycle app filter, `y` copy details / `u` copy URL to clipboard (OSC 52, e.g. kitty), `b` browser launch command (MITM), space pause, q quit.

Limits: sniffer sees hostnames only for HTTPS and does not parse HTTP/3 (QUIC); the proxy handles HTTPS (CONNECT) over HTTP/1.1, requests only, not plain-HTTP proxying. App names come from `/proc` (Linux, best effort).
