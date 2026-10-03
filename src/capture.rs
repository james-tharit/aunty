//! Packet capture + parsing: each packet that names a host becomes a `Hit`.
use etherparse::{NetHeaders, PacketHeaders, TransportHeader::*};
use pcap::{Active, Capture, Device};
use std::{
    net::IpAddr,
    sync::{atomic::{AtomicU64, Ordering::Relaxed}, mpsc::Sender},
    thread,
};

/// Every packet the NIC delivered, parsed or not (shown in the title to tell "capture dead" from "nothing parsed").
pub static SEEN: AtomicU64 = AtomicU64::new(0);

pub struct Hit {
    pub host: String,
    pub source: &'static str, // "TLS" | "HTTP" | "DNS"
    pub ip: Option<IpAddr>,
    pub port: u16,
    pub bytes: u32,
    pub http: Option<Http>,
}

#[derive(Clone)]
pub struct Http {
    pub method: String,
    pub path: String,
    pub query: Vec<(String, String)>,
    pub headers: Vec<(String, String)>,
    pub body: String,
}

pub fn interfaces() -> Result<Vec<String>, pcap::Error> {
    Ok(Device::list()?.into_iter().map(|d| d.name).collect())
}

pub fn open(name: &str) -> Result<Capture<Active>, pcap::Error> {
    Capture::from_device(name)?.immediate_mode(true).open()
}

pub fn spawn(mut cap: Capture<Active>, tx: Sender<Hit>) {
    thread::spawn(move || {
        while let Ok(pkt) = cap.next_packet() {
            SEEN.fetch_add(1, Relaxed);
            if let Some(hit) = inspect(pkt.data, pkt.header.len) {
                if tx.send(hit).is_err() {
                    break;
                }
            }
        }
    });
}

fn inspect(data: &[u8], bytes: u32) -> Option<Hit> {
    let h = PacketHeaders::from_ethernet_slice(data).ok()?;
    let ip = match h.net {
        Some(NetHeaders::Ipv4(ip, _)) => Some(IpAddr::from(ip.destination)),
        Some(NetHeaders::Ipv6(ip, _)) => Some(IpAddr::from(ip.destination)),
        _ => None,
    };
    let body = h.payload.slice();
    let (port, source, host, http, ip) = match h.transport? {
        Tcp(t) => match sni(body) {
            Some(host) => (t.destination_port, "TLS", host, None, ip),
            None => {
                let (host, req) = http(body)?;
                (t.destination_port, "HTTP", host, Some(req), ip)
            }
        },
        // dest of a DNS query is the resolver, not the host
        Udp(u) if u.destination_port == 53 => (53, "DNS", dns_query(body)?, None, None),
        _ => return None,
    };
    Some(Hit { host, source, ip, port, bytes, http })
}

fn take<'a>(b: &mut &'a [u8], n: usize) -> Option<&'a [u8]> {
    let (head, rest) = b.split_at_checked(n)?;
    *b = rest;
    Some(head)
}

fn be(b: &[u8]) -> usize {
    b.iter().fold(0, |a, &x| a << 8 | x as usize)
}

/// Server name from a TLS ClientHello.
fn sni(mut b: &[u8]) -> Option<String> {
    let hdr = take(&mut b, 6)?; // record header + handshake type
    if hdr[0] != 0x16 || hdr[5] != 1 { return None; }
    take(&mut b, 37)?; // handshake length, version, random
    let n = take(&mut b, 1)?[0] as usize; take(&mut b, n)?; // session id
    let n = be(take(&mut b, 2)?); take(&mut b, n)?; // cipher suites
    let n = take(&mut b, 1)?[0] as usize; take(&mut b, n)?; // compression
    let n = be(take(&mut b, 2)?);
    // Chrome's ClientHello often spills into a 2nd segment: parse what this packet holds
    let mut ext = &b[..n.min(b.len())];
    while !ext.is_empty() {
        let ty = be(take(&mut ext, 2)?);
        let n = be(take(&mut ext, 2)?);
        let mut body = take(&mut ext, n)?;
        if ty == 0 {
            take(&mut body, 3)?; // list len, name type
            let n = be(take(&mut body, 2)?);
            return String::from_utf8(take(&mut body, n)?.to_vec()).ok();
        }
    }
    None
}

/// Plain HTTP/1.x request: (host, parsed request). Body is whatever fits in this packet.
fn http(b: &[u8]) -> Option<(String, Http)> {
    let s = String::from_utf8_lossy(b);
    let (head, body) = s.split_once("\r\n\r\n").unwrap_or((s.as_ref(), ""));
    let mut lines = head.lines();
    let mut first = lines.next()?.split(' ');
    let (method, target, ver) = (first.next()?, first.next()?, first.next()?);
    if !ver.starts_with("HTTP/") || !method.bytes().all(|c| c.is_ascii_uppercase()) { return None; }
    let headers: Vec<(String, String)> = lines
        .filter_map(|l| l.split_once(": "))
        .map(|(k, v)| (k.into(), v.into()))
        .collect();
    let host = headers.iter().find(|(k, _)| k.eq_ignore_ascii_case("host"))?.1.clone();
    let (path, q) = target.split_once('?').unwrap_or((target, ""));
    let query = q
        .split('&')
        .filter(|p| !p.is_empty())
        .map(|p| p.split_once('=').unwrap_or((p, "")))
        .map(|(k, v)| (k.into(), v.into()))
        .collect();
    Some((host, Http { method: method.into(), path: path.into(), query, headers, body: body.into() }))
}

/// First question name of a DNS query.
fn dns_query(mut b: &[u8]) -> Option<String> {
    if take(&mut b, 12)?[2] & 0x80 != 0 { return None; } // response, not query
    let mut labels = vec![];
    loop {
        let n = take(&mut b, 1)?[0] as usize;
        if n == 0 { break; }
        labels.push(String::from_utf8(take(&mut b, n)?.to_vec()).ok()?);
    }
    (!labels.is_empty()).then(|| labels.join("."))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_dns_and_http() {
        let mut q = vec![0u8; 12];
        q.extend(b"\x03www\x06google\x03com\x00\x00\x01\x00\x01");
        assert_eq!(dns_query(&q).unwrap(), "www.google.com");

        let (host, r) = http(b"GET /a?x=1&y=2 HTTP/1.1\r\nHost: example.com\r\n\r\nhi").unwrap();
        assert_eq!(host, "example.com");
        assert_eq!(r.query, [("x".into(), "1".into()), ("y".into(), "2".into())]);
        assert_eq!(r.body, "hi");
        assert!(http(b"HTTP/1.1 200 OK\r\nHost: a\r\n\r\n").is_none());
    }
}
