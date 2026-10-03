//! Local MITM proxy for your own browser: terminates TLS with a throwaway CA, reads each
//! HTTP/1.1 request (full URL, headers, body), and forwards it to the real server over TLS.
//! ponytail: CONNECT only, HTTP/1.1 only (ALPN forced), request side only, CA is in-memory
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
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};
use tokio_rustls::{TlsAcceptor, TlsConnector};

type Res<T> = Result<T, Box<dyn Error + Send + Sync>>;

struct Ca {
    cert: Certificate,
    key: KeyPair,
    leaves: Mutex<HashMap<String, Arc<ServerConfig>>>,
}

impl Ca {
    fn new() -> Res<Self> {
        let mut p = CertificateParams::default();
        p.distinguished_name.push(DnType::CommonName, "aunty MITM CA");
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

async fn handle(mut c: TcpStream, peer: SocketAddr, ca: Arc<Ca>, connector: TlsConnector, tx: Sender<Hit>) {
    let _ = tunnel(&mut c, peer, &ca, &connector, &tx).await; // errors = a connection that died; nothing to report
}

async fn tunnel(c: &mut TcpStream, peer: SocketAddr, ca: &Ca, connector: &TlsConnector, tx: &Sender<Hit>) -> Res<()> {
    let mut buf = vec![0u8; 16384];
    let n = c.read(&mut buf).await?;
    let target = std::str::from_utf8(&buf[..n])?
        .strip_prefix("CONNECT ")
        .ok_or("only CONNECT (HTTPS) is supported")?
        .split(' ')
        .next()
        .unwrap_or("");
    let (host, port) = target.rsplit_once(':').ok_or("bad CONNECT target")?;
    let (host, port) = (host.to_string(), port.parse::<u16>()?);
    c.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n").await?;

    let client = TlsAcceptor::from(ca.config(&host)?).accept(c).await?;
    let up = TcpStream::connect((host.as_str(), port)).await?;
    let ip = up.peer_addr()?.ip();
    let server = connector.connect(ServerName::try_from(host.clone())?, up).await?;
    let app = proc::app_for(false, peer.port()); // the browser's socket

    let (mut cr, mut cw) = tokio::io::split(client);
    let (mut sr, mut sw) = tokio::io::split(server);
    let upstream = async {
        loop {
            let n = cr.read(&mut buf).await?;
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
