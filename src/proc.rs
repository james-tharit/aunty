//! Which process owns a local socket: /proc/net/{tcp,udp} port -> inode, then /proc/*/fd -> pid -> comm.
//! ponytail: scans /proc per hit (not per packet); cache by port if capture starts dropping packets.
use std::fs;

pub fn app_for(udp: bool, port: u16) -> Option<String> {
    let target = format!("socket:[{}]", inode(udp, port)?);
    for p in fs::read_dir("/proc").ok()?.flatten() {
        let Ok(fds) = fs::read_dir(p.path().join("fd")) else { continue };
        if fds.flatten().any(|fd| fs::read_link(fd.path()).is_ok_and(|l| l.to_str() == Some(&target))) {
            return fs::read_to_string(p.path().join("comm")).ok().map(|s| s.trim().into());
        }
    }
    None
}

fn inode(udp: bool, port: u16) -> Option<u64> {
    let suffix = format!(":{port:04X}");
    let files = if udp { ["udp", "udp6"] } else { ["tcp", "tcp6"] };
    files.iter().find_map(|f| {
        fs::read_to_string(format!("/proc/net/{f}")).ok()?.lines().skip(1).find_map(|l| {
            let c: Vec<&str> = l.split_whitespace().collect();
            let ino: u64 = c.get(9)?.parse().ok()?;
            (c.get(1)?.ends_with(&suffix) && ino != 0).then_some(ino)
        })
    })
}

#[cfg(test)]
#[test]
fn finds_own_socket() {
    let s = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let name = app_for(true, s.local_addr().unwrap().port()).expect("owner found");
    assert!(std::env::current_exe().unwrap().file_name().unwrap().to_str().unwrap().starts_with(&name[..name.len().min(15)]));
}

#[cfg(test)]
#[test]
fn finds_own_tcp_client() {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let c = std::net::TcpStream::connect(l.local_addr().unwrap()).unwrap();
    assert!(app_for(false, c.local_addr().unwrap().port()).is_some());
}
