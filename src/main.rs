use pcap::Device;
use std::net::{Ipv4Addr, Ipv6Addr};
use etherparse::PacketHeaders;

fn main() {
    let mut cap = Device::lookup()
        .unwrap()
        .expect("No device found")
        .open()
        .unwrap();

    println!("{:<10} | {:<40} | {:<40} | {:<10} | {:<10}", "Proto", "Source", "Destination", "Info/Port", "Length");
    println!("{:-<115}", "");

    while let Ok(packet) = cap.next_packet() {
        // Parse the packet data starting from the Ethernet layer
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
                            source = Ipv4Addr::from(ipv4.source).to_string();
                            dest = Ipv4Addr::from(ipv4.destination).to_string();
                            proto = String::from("IPv4");
                        }
                        etherparse::NetHeaders::Ipv6(ipv6, _) => {
                            source = Ipv6Addr::from(ipv6.source).to_string();
                            dest = Ipv6Addr::from(ipv6.destination).to_string();
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
                            proto = format!("{}/UDP", proto);
                            info = format!("{}->{}", udp.source_port, udp.destination_port);
                        }
                        _ => {}
                    }
                }

                // 3. Pretty Print the row
                println!(
                    "{:<10} | {:<40} | {:<40} | {:<10} | {:<10}",
                    proto, 
                    source, 
                    dest, 
                    info, 
                    packet.header.len
                );
            }
            Err(_) => {
                // Skips non-ethernet packets or malformed data
                continue;
            }
        }
    }
}