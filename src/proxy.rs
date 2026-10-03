//! Local MITM proxy for your own browser: terminates TLS with a throwaway CA, reads each
//! HTTP/1.1 request (full URL, headers, body), and forwards it to the real server over TLS.
//! The CA is persisted in `dir()` so a browser profile can trust it once; it is trusted only
//! in the throwaway Firefox profile (or Chrome with --ignore-certificate-errors), never system-wide.
//! ponytail: CONNECT only, HTTP/1.1 only (ALPN forced), request side only; add responses when needed.
use crate::{capture::{self, Hit}, proc};
use rcgen::{BasicConstraints, Certificate, CertificateParams, DnType, IsCa, KeyPair, KeyUsagePurpose};
use rustls::{
    pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer, ServerName},
    ClientConfig, RootCertStore, ServerConfig,
};
use std::{
    collections::HashMap,
    error::Error,
    fs,
    net::SocketAddr,
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
    process::Command,
    sync::{mpsc::Sender, Arc, Mutex},
    thread,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};
use tokio_rustls::{TlsAcceptor, TlsConnector};

type Res<T> = Result<T, Box<dyn Error + Send + Sync>>;

pub const ADDR: &str = "127.0.0.1:8080";
const CA_NAME: &str = "aunty MITM CA";

/// ~/.config/aunty: CA files and the Firefox profile.
pub fn dir() -> PathBuf {
    std::env::var_os("HOME").map_or("/tmp".into(), PathBuf::from).join(".config/aunty")
}

/// Create a throwaway Firefox profile that uses the proxy. Returns (profile dir, note about CA trust).
pub fn firefox_profile(dir: &Path) -> (PathBuf, String) {
    let prof = dir.join("firefox");
    let (host, port) = ADDR.rsplit_once(':').unwrap();
    let _ = fs::create_dir_all(&prof);
    let _ = fs::write(
        prof.join("user.js"),
        format!(
            "user_pref(\"network.proxy.type\", 1);\n\
             user_pref(\"network.proxy.http\", \"{host}\");\nuser_pref(\"network.proxy.http_port\", {port});\n\
             user_pref(\"network.proxy.ssl\", \"{host}\");\nuser_pref(\"network.proxy.ssl_port\", {port});\n\
             user_pref(\"network.http.http3.enable\", false);\n\
             user_pref(\"browser.shell.checkDefaultBrowser\", false);\n"
        ),
    );
    // best effort: needs certutil (apt install libnss3-tools)
    let db = format!("sql:{}", prof.display());
    let ca = dir.join("ca.pem");
    let certutil = |a: &[&str]| Command::new("certutil").args(a).output().is_ok_and(|o| o.status.success());
    if !prof.join("cert9.db").exists() {
        certutil(&["-N", "-d", &db, "--empty-password"]);
    }
    let trusted = certutil(&["-L", "-d", &db, "-n", CA_NAME])
        || certutil(&["-A", "-n", CA_NAME, "-t", "C,,", "-i", &ca.to_string_lossy(), "-d", &db]);
    let note = if trusted {
        "CA already trusted in this profile.".into()
    } else {
        format!("First time only: Firefox > Settings > Certificates > View Certificates > Authorities > Import {} (trust for websites). Or: apt install libnss3-tools and restart aunty.", ca.display())
    };
    (prof, note)
}

struct Ca {
    cert: Certificate,
    key: KeyPair,
    leaves: Mutex<HashMap<String, Arc<ServerConfig>>>,
}

impl Ca {
    /// Load the CA from `dir`, or create and save it.
    fn load_or_create(dir: &Path) -> Res<Self> {
        fs::create_dir_all(dir)?;
        let (pem_path, key_path) = (dir.join("ca.pem"), dir.join("ca.key"));
        if let (Ok(pem), Ok(key)) = (fs::read_to_string(&pem_path), fs::read_to_string(&key_path)) {
            let key = KeyPair::from_pem(&key)?;
            // same subject + key as the saved cert, so leaves still chain to what the browser trusts
            let cert = CertificateParams::from_ca_cert_pem(&pem)?.self_signed(&key)?;
            return Ok(Self { cert, key, leaves: Default::default() });
        }
        let mut p = CertificateParams::default();
        p.distinguished_name.push(DnType::CommonName, CA_NAME);
        p.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        p.key_usages = vec![KeyUsagePurpose::KeyCertSign];
        let key = KeyPair::generate()?;
        let cert = p.self_signed(&key)?;
        fs::write(&pem_path, cert.pem())?;
        // the key can impersonate any site to a browser that trusts the CA: owner-only
        use std::io::Write;
        fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(&key_path)?.write_all(key.serialize_pem().as_bytes())?;
        Ok(Self { cert, key, leaves: Default::default() })
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

pub fn spawn(listener: std::net::TcpListener, dir: &Path, tx: Sender<Hit>) -> Res<()> {
    let ca = Arc::new(Ca::load_or_create(dir)?);
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

#[test]
fn ca_persists_across_loads() {
    let d = std::env::temp_dir().join(format!("aunty-test-{}", std::process::id()));
    Ca::load_or_create(&d).unwrap();
    let (pem, key) = (fs::read(d.join("ca.pem")).unwrap(), fs::read(d.join("ca.key")).unwrap());
    let ca = Ca::load_or_create(&d).unwrap();
    assert_eq!((pem, key), (fs::read(d.join("ca.pem")).unwrap(), fs::read(d.join("ca.key")).unwrap()));
    ca.config("example.com").unwrap();
    fs::remove_dir_all(d).unwrap();
}
