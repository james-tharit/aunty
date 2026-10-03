//! Local MITM proxy for your own browser: terminates TLS with a throwaway CA, reads each
//! HTTP/1.1 request (full URL, headers, body), and forwards it to the real server over TLS.
//! ponytail: CONNECT + plain absolute-form http, HTTP/1.1 only (ALPN forced), request side only, CA is in-memory
//! (browser must ignore cert errors); persist the CA / add responses when needed.
use crate::{capture::{self, Hit}, proc};
use rcgen::{BasicConstraints, Certificate, CertificateParams, DnType, IsCa, KeyPair, KeyUsagePurpose};
use rustls::{
    pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer, ServerName},
    ClientConfig, RootCertStore, ServerConfig,
};
use std::{
    collections::HashMap,
    error::Error,
    net::SocketAddr,
    sync::{mpsc::Sender, Arc, Mutex},
    thread,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};
use tokio_rustls::{TlsAcceptor, TlsConnector};

trait AsyncStream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> AsyncStream for T {}

type Res<T> = Result<T, Box<dyn Error + Send + Sync>>;

pub const ADDR: &str = "127.0.0.1:8080";

struct Ca {
    cert: Certificate,
    key: KeyPair,
    leaves: Mutex<HashMap<String, Arc<ServerConfig>>>,
}

impl Ca {
    fn new() -> Res<Self> {
        let mut p = CertificateParams::default();
        p.distinguished_name.push(DnType::CommonName, "whotalk MITM CA");
        p.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        p.key_usages = vec![KeyUsagePurpose::KeyCertSign];
        let key = KeyPair::generate()?;
        Ok(Self { cert: p.self_signed(&key)?, key, leaves: Default::default() })
    }

    /// TLS server config presenting a certificate for `host`, signed by our CA.
    fn config(&self, host: &str) -> Res<Arc<ServerConfig>> {
        if let Some(c) = self.leaves.lock().unwrap().get(host) {
            return Ok(c.clone());
        }
        let leaf_key = KeyPair::generate()?;
        let leaf = CertificateParams::new(vec![host.to_string()])?.signed_by(&leaf_key, &self.cert, &self.key)?;
        let mut cfg = ServerConfig::builder().with_no_client_auth().with_single_cert(
            vec![leaf.der().clone()],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der())),
        )?;
        cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
        let cfg = Arc::new(cfg);
        self.leaves.lock().unwrap().insert(host.into(), cfg.clone());
        Ok(cfg)
    }
}

pub fn spawn(listener: std::net::TcpListener, tx: Sender<Hit>) -> Res<()> {
    let ca = Arc::new(Ca::new()?);
    let mut cfg = ClientConfig::builder()
        .with_root_certificates(RootCertStore { roots: webpki_roots::TLS_SERVER_ROOTS.to_vec() })
        .with_no_client_auth();
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    let connector = TlsConnector::from(Arc::new(cfg));
    thread::spawn(move || {
        tokio::runtime::Runtime::new().unwrap().block_on(async move {
            let l = TcpListener::from_std(listener).unwrap();
            while let Ok((s, peer)) = l.accept().await {
                tokio::spawn(handle(s, peer, ca.clone(), connector.clone(), tx.clone()));
            }
        });
    });
    Ok(())
}

async fn handle(c: TcpStream, peer: SocketAddr, ca: Arc<Ca>, connector: TlsConnector, tx: Sender<Hit>) {
    let _ = tunnel(c, peer, &ca, &connector, &tx).await; // errors = a connection that died; nothing to report
}

async fn tunnel(mut c: TcpStream, peer: SocketAddr, ca: &Ca, connector: &TlsConnector, tx: &Sender<Hit>) -> Res<()> {
    let mut buf = vec![0u8; 16384];
    let n = c.read(&mut buf).await?;
    let head = std::str::from_utf8(&buf[..n])?;
    type Io = Box<dyn AsyncStream>;
    let (host, port, client, server, ip, mut first): (String, u16, Io, Io, _, Vec<u8>);
    if let Some(rest) = head.strip_prefix("CONNECT ") {
        let target = rest.split(' ').next().unwrap_or("");
        let (h, p) = target.rsplit_once(':').ok_or("bad CONNECT target")?;
        (host, port) = (h.to_string(), p.parse::<u16>()?);
        c.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n").await?;
        client = Box::new(TlsAcceptor::from(ca.config(&host)?).accept(c).await?);
        let up = TcpStream::connect((host.as_str(), port)).await?;
        ip = up.peer_addr()?.ip();
        server = Box::new(connector.connect(ServerName::try_from(host.clone())?, up).await?);
        first = vec![];
    } else {
        // plain http:// request in absolute form ("GET http://host[:port]/path HTTP/1.1"): forward as-is
        let url = head.split(' ').nth(1).and_then(|u| u.strip_prefix("http://")).ok_or("unsupported proxy request")?;
        let authority = url.split('/').next().unwrap_or("");
        (host, port) = match authority.rsplit_once(':') {
            Some((h, p)) => (h.to_string(), p.parse::<u16>()?),
            None => (authority.to_string(), 80),
        };
        let up = TcpStream::connect((host.as_str(), port)).await?;
        ip = up.peer_addr()?.ip();
        server = Box::new(up);
        client = Box::new(c);
        first = buf[..n].to_vec();
    }
    let app = proc::app_for(false, peer.port()); // the browser's socket

    let (mut cr, mut cw) = tokio::io::split(client);
    let (mut sr, mut sw) = tokio::io::split(server);
    let upstream = async {
        loop {
            let n = if first.is_empty() { cr.read(&mut buf).await? } else { buf[..first.len()].copy_from_slice(&first); std::mem::take(&mut first).len() };
            if n == 0 {
                break;
            }
            if let Some((_, req)) = capture::http(&buf[..n]) {
                let _ = tx.send(Hit {
                    host: host.clone(), source: "MITM", ip: Some(ip), port, bytes: n as u32, http: Some(req), app: app.clone(),
                });
            }
            sw.write_all(&buf[..n]).await?;
        }
        sw.shutdown().await
    };
    tokio::select! {
        r = upstream => r?,
        r = tokio::io::copy(&mut sr, &mut cw) => { r?; }
    }
    Ok(())
}
