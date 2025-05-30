use clap::{Parser, Subcommand};
use pcap::{Device, Capture};
use etherparse::{SlicedPacket, InternetSlice, TransportSlice};

#[derive(Parser)]
#[command(name = "rudeus")]
#[command(about = "A simple, modern, and fast CLI tool to monitor network traffic in real-time", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// List all available network interfaces
    List,
    /// Capture packets from a specific interface
    Capture {
        /// Name of the interface to capture from
        #[arg(short, long)]
        interface: String,
    },
}

fn main() {
    let cli = Cli::parse();
    match &cli.command {
        Commands::List => {
            match Device::list() {
                Ok(devices) => {
                    println!("Available interfaces:");
                    for dev in devices {
                        if let Some(desc) = &dev.desc {
                            println!("- {} ({})", dev.name, desc);
                        } else {
                            println!("- {}", dev.name);
                        }
                    }
                }
                Err(e) => {
                    eprintln!("Failed to list devices: {}", e);
                }
            }
        }
        Commands::Capture { interface } => {
            println!("Capturing on interface: {}", interface);
            let mut cap = match Capture::from_device(interface.as_str())
                .unwrap()
                .promisc(true)
                .immediate_mode(true)
                .open()
            {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("Failed to open device: {}", e);
                    return;
                }
            };
            println!("Press Ctrl+C to stop.");
            let mut packet_count = 0;
            while let Ok(packet) = cap.next_packet() {
                packet_count += 1;
                println!("\n[Packet #{}] {} bytes", packet_count, packet.header.len);
                match SlicedPacket::from_ethernet(packet.data) {
                    Ok(sliced) => {
                        // Link Layer
                        if let Some(link) = &sliced.link {
                            println!("Link: {:?}", link);
                        }
                        // Network Layer
                        match &sliced.ip {
                            Some(InternetSlice::Ipv4(ipv4, _)) => {
                                println!("IPv4: {} -> {}", ipv4.source_addr(), ipv4.destination_addr());
                                println!("Protocol: {}", ipv4.protocol());
                            }
                            Some(InternetSlice::Ipv6(ipv6, _)) => {
                                println!("IPv6: {} -> {}", 
                                    std::net::Ipv6Addr::from(ipv6.source_addr()),
                                    std::net::Ipv6Addr::from(ipv6.destination_addr())
                                );
                                println!("Next Header: {}", ipv6.next_header());
                            }
                            None => println!("No IP layer found"),
                        }
                        // Transport Layer
                        match &sliced.transport {
                            Some(TransportSlice::Tcp(tcp)) => {
                                println!("TCP: {} -> {}", tcp.source_port(), tcp.destination_port());
                                println!("Flags: SYN={} ACK={} FIN={} RST={}", tcp.syn(), tcp.ack(), tcp.fin(), tcp.rst());
                                println!("Seq: {}, Window: {}", tcp.sequence_number(), tcp.window_size());
                                // Cek HTTP/HTTPS request di semua port
                                if let Ok(http_str) = std::str::from_utf8(&sliced.payload) {
                                    if let Some(line) = http_str.lines().next() {
                                        // Deteksi HTTP request
                                        let methods = ["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "CONNECT", "TRACE"];
                                        if methods.iter().any(|m| line.starts_with(m)) {
                                            let mut parts = line.split_whitespace();
                                            let method = parts.next().unwrap_or("");
                                            let url = parts.next().unwrap_or("");
                                            println!("HTTP Request: {} {}", method, url);
                                            // Cari Host header
                                            for l in http_str.lines() {
                                                if l.to_ascii_lowercase().starts_with("host:") {
                                                    println!("Host: {}", l[5..].trim());
                                                    break;
                                                }
                                            }
                                        }
                                    }
                                } else if !sliced.payload.is_empty() && sliced.payload[0] == 0x16 && sliced.payload.len() > 5 && sliced.payload[1] == 0x03 {
                                    // TLS handshake (indikasi HTTPS)
                                    println!("Possible TLS/HTTPS traffic detected (TLS handshake)");
                                }
                            }
                            Some(TransportSlice::Udp(udp)) => {
                                println!("UDP: {} -> {}", udp.source_port(), udp.destination_port());
                                println!("Length: {}", udp.length());
                            }
                            Some(TransportSlice::Icmpv4(_)) => println!("ICMPv4 packet"),
                            Some(TransportSlice::Icmpv6(_)) => println!("ICMPv6 packet"),
                            Some(TransportSlice::Unknown(u)) => println!("Unknown transport protocol: {}", u),
                            None => println!("No transport layer found"),
                        }
                        // Payload
                        let payload = &sliced.payload;
                        if !payload.is_empty() {
                            println!("Payload: {} bytes", payload.len());
                            let preview_len = std::cmp::min(16, payload.len());
                            print!("Preview: ");
                            for byte in &payload[0..preview_len] {
                                print!("{:02x} ", byte);
                            }
                            println!();
                        } else {
                            println!("Payload: empty");
                        }
                    }
                    Err(err) => println!("Error parsing packet: {:?}", err),
                }
            }
        }
    }
} 