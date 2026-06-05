use pcap::Device;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use etherparse::PacketHeaders;
use std::sync::mpsc::Sender;
use crate::packet::PacketInfo;

/// Perform DNS lookup and return hostname or IP address
fn format_ip_with_dns(ip: IpAddr) -> String {
    match dns_lookup::lookup_addr(&ip) {
        Ok(hostname) => {
            // Strip domain suffix — only keep the short hostname
            let short = hostname.split('.').next().unwrap_or(&hostname);
            format!("{} ({})", short, ip)
        }
        Err(_) => ip.to_string(),
    }
}

/// Start the packet capture thread
/// This runs in a separate thread and sends captured packets through the channel
pub fn start_capture_thread(tx: Sender<PacketInfo>) {
    std::thread::spawn(move || {
        let mut cap = match Device::lookup() {
            Ok(Some(device)) => match device.open() {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("Failed to open device: {}", e);
                    return;
                }
            },
            Ok(None) => {
                eprintln!("No device found");
                return;
            }
            Err(e) => {
                eprintln!("Device lookup failed: {}", e);
                return;
            }
        };

        while let Ok(packet) = cap.next_packet() {
            match PacketHeaders::from_ethernet_slice(&packet.data) {
                Ok(headers) => {
                    let mut source = String::from("Unknown");
                    let mut dest = String::from("Unknown");
                    let mut proto = String::from("Other");
                    let mut info = String::from("-");

                    // 1. IP Layer Info
                    if let Some(net) = headers.net {
                        match net {
                            etherparse::NetHeaders::Ipv4(ipv4, _) => {
                                source = format_ip_with_dns(IpAddr::V4(Ipv4Addr::from(ipv4.source)));
                                dest = format_ip_with_dns(IpAddr::V4(Ipv4Addr::from(ipv4.destination)));
                                proto = String::from("IPv4");
                            }
                            etherparse::NetHeaders::Ipv6(ipv6, _) => {
                                source = format_ip_with_dns(IpAddr::V6(Ipv6Addr::from(ipv6.source)));
                                dest = format_ip_with_dns(IpAddr::V6(Ipv6Addr::from(ipv6.destination)));
                                proto = String::from("IPv6");
                            }
                            etherparse::NetHeaders::Arp(_) => {
                                proto = String::from("ARP");
                            }
                        }
                    }

                    // 2. Transport Layer Info (Ports)
                    if let Some(transport) = headers.transport {
                        #[allow(unreachable_patterns)]
                        match transport {
                            etherparse::TransportHeader::Tcp(tcp) => {
                                proto = format!("{}/TCP", proto);
                                info = format!("{}->{}", tcp.source_port, tcp.destination_port);
                            }
                            etherparse::TransportHeader::Udp(udp) => {
                                // Skip DNS traffic (port 53)
                                if udp.source_port == 53 || udp.destination_port == 53 {
                                    continue;
                                }
                                proto = format!("{}/UDP", proto);
                                info = format!("{}->{}", udp.source_port, udp.destination_port);
                            }
                            _ => {}
                        }
                    }

                    let packet_info = PacketInfo::new(
                        proto,
                        source,
                        dest,
                        info,
                        packet.header.len,
                    );

                    // Send packet to the UI thread - ignore if receiver is closed
                    let _ = tx.send(packet_info);
                }
                Err(_) => {
                    // Skips non-ethernet packets or malformed data
                    continue;
                }
            }
        }
    });
}
