use etherparse::{InternetSlice, SlicedPacket, TransportSlice};
use pcap::{Capture, Savefile};
use std::path::Path;

pub struct PacketCapture {
    interface: String,
    save_to_file: bool,
    output_dir: String,
}

impl PacketCapture {
    pub fn new(interface: &str) -> Self {
        Self {
            interface: interface.to_string(),
            save_to_file: false,
            output_dir: ".".to_string(),
        }
    }

    pub fn set_save_options(&mut self, output_dir: &str) {
        self.save_to_file = true;
        self.output_dir = output_dir.to_string();
    }

    pub fn start_capture(&mut self) {
        println!("Capturing on interface: {}", self.interface);

        let cap = match Capture::from_device(self.interface.as_str())
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

        let mut savefile = if self.save_to_file {
            match self.create_savefile(&cap) {
                Ok(sf) => {
                    println!("Saving packets to: {}", self.get_output_filename());
                    Some(sf)
                }
                Err(e) => {
                    eprintln!("Failed to create save file: {}", e);
                    return;
                }
            }
        } else {
            None
        };

        println!("Press Ctrl+C to stop.");

        // Convert cap to mutable for packet capture
        let mut cap = cap;

        loop {
            match cap.next_packet() {
                Ok(packet) => {
                    // Save packet to file if enabled
                    if let Some(ref mut sf) = savefile {
                        sf.write(&packet);
                        // Flush periodically to ensure data is written
                        if let Err(e) = sf.flush() {
                            eprintln!("Failed to flush packets to file: {}", e);
                        }
                    }

                    let packet_info = self.parse_packet(&packet);
                    self.display_packet(&packet_info);
                }
                Err(e) => {
                    eprintln!("Warning: {}", e);
                    continue;
                }
            }
        }
    }

    fn create_savefile(
        &self,
        cap: &Capture<pcap::Active>,
    ) -> Result<Savefile, Box<dyn std::error::Error>> {
        // Check if output directory exists, create if it doesn't
        if !Path::new(&self.output_dir).exists() {
            std::fs::create_dir_all(&self.output_dir)?;
        }

        let filename = self.get_output_filename();
        let savefile = cap.savefile(&filename)?;
        Ok(savefile)
    }

    fn get_output_filename(&self) -> String {
        let now = chrono::Local::now();
        let date_time = now.format("%Y%m%d_%H%M%S").to_string();
        let filename = format!("dump_{}.pcap", date_time);
        Path::new(&self.output_dir)
            .join(filename)
            .to_string_lossy()
            .to_string()
    }

    fn parse_packet(&self, packet: &pcap::Packet) -> PacketInfo {
        let mut info = PacketInfo {
            protocol: String::from("tcp"),
            src_ip: String::from("-"),
            dst_ip: String::from("-"),
            timestamp: chrono::Local::now()
                .format("%Y/%m/%d %H:%M:%S %:z")
                .to_string(),
            dst_port: 0u16,
            bytes: packet.header.len as usize,
            ip_protocol: String::from("tcp"),
            data_bytes: 0usize,
        };

        if let Ok(sliced) = SlicedPacket::from_ethernet(packet.data) {
            // Parse IP layer
            match &sliced.ip {
                Some(InternetSlice::Ipv4(ipv4, _)) => {
                    info.src_ip = ipv4.source_addr().to_string();
                    info.dst_ip = ipv4.destination_addr().to_string();
                }
                Some(InternetSlice::Ipv6(ipv6, _)) => {
                    info.src_ip = std::net::Ipv6Addr::from(ipv6.source_addr()).to_string();
                    info.dst_ip = std::net::Ipv6Addr::from(ipv6.destination_addr()).to_string();
                }
                _ => {}
            }

            // Parse transport layer
            match &sliced.transport {
                Some(TransportSlice::Tcp(tcp)) => {
                    info.dst_port = tcp.destination_port();
                    info.data_bytes = sliced.payload.len();
                }
                Some(TransportSlice::Udp(udp)) => {
                    info.protocol = String::from("udp");
                    info.ip_protocol = String::from("udp");
                    info.dst_port = udp.destination_port();
                    info.data_bytes = sliced.payload.len();
                }
                _ => {}
            }
        }

        info
    }

    fn display_packet(&self, info: &PacketInfo) {
        println!(
            "{} | {} | {} | {} | {:<7} | {:<5} | {:<10} | {}",
            info.protocol,
            info.src_ip,
            info.dst_ip,
            info.timestamp,
            info.dst_port,
            info.bytes,
            info.ip_protocol,
            info.data_bytes
        );
    }
}

struct PacketInfo {
    protocol: String,
    src_ip: String,
    dst_ip: String,
    timestamp: String,
    dst_port: u16,
    bytes: usize,
    ip_protocol: String,
    data_bytes: usize,
}
