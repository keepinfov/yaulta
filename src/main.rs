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
            loop {
                match cap.next_packet() {
                    Ok(packet) => {
                        let mut protocol = String::from("tcp");
                        let mut src_ip = String::from("-");
                        let mut dst_ip = String::from("-");
                        let stop_time = chrono::Local::now().format("%Y/%m/%d %H:%M:%S %:z").to_string();
                        let mut dst_port = 0u16;
                        let bytes = packet.header.len as usize;
                        let mut ip_protocol = String::from("tcp");
                        let mut data_bytes = 0usize;
                        if let Ok(sliced) = SlicedPacket::from_ethernet(packet.data) {
                            match &sliced.ip {
                                Some(InternetSlice::Ipv4(ipv4, _)) => {
                                    src_ip = ipv4.source_addr().to_string();
                                    dst_ip = ipv4.destination_addr().to_string();
                                }
                                Some(InternetSlice::Ipv6(ipv6, _)) => {
                                    src_ip = std::net::Ipv6Addr::from(ipv6.source_addr()).to_string();
                                    dst_ip = std::net::Ipv6Addr::from(ipv6.destination_addr()).to_string();
                                }
                                _ => {}
                            }
                            match &sliced.transport {
                                Some(TransportSlice::Tcp(tcp)) => {
                                    dst_port = tcp.destination_port();
                                    data_bytes = sliced.payload.len();
                                }
                                Some(TransportSlice::Udp(udp)) => {
                                    protocol = String::from("udp");
                                    ip_protocol = String::from("udp");
                                    dst_port = udp.destination_port();
                                    data_bytes = sliced.payload.len();
                                }
                                _ => {}
                            }
                        }
                        println!("{} | {} | {} | {} | {:<7} | {:<5} | {:<10} | {}", protocol, src_ip, dst_ip, stop_time, dst_port, bytes, ip_protocol, data_bytes);
                    }
                    Err(e) => {
                        eprintln!("Warning: {}", e);
                        continue;
                    }
                }
            }
        }
    }
} 