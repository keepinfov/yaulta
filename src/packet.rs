use async_nats::{jetstream::Context, HeaderMap};
use bytes::Bytes;
use etherparse::{InternetSlice, SlicedPacket, TransportSlice};
use pcap::{Capture, Savefile};
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Serialize, Deserialize)]
pub struct PacketData {
    pub timestamp: String,
    pub protocol: String,
    pub src_ip: String,
    pub dst_ip: String,
    pub dst_port: u16,
    pub bytes: usize,
    pub ip_protocol: String,
    pub data_bytes: usize,
    pub raw_data: Vec<u8>,
}

pub struct PacketCapture {
    interface: String,
    save_to_file: bool,
    output_dir: String,
    nats_enabled: bool,
    jetstream: Option<Context>,
    node_id: Option<String>,
    subject: String,
}

impl PacketCapture {
    pub async fn new(interface: &str) -> Result<Self, Box<dyn std::error::Error>> {
        Ok(Self {
            interface: interface.to_string(),
            save_to_file: false,
            output_dir: ".".to_string(),
            nats_enabled: false,
            jetstream: None,
            node_id: None,
            subject: "network.packets".to_string(),
        })
    }

    pub fn set_save_options(&mut self, output_dir: &str) {
        self.save_to_file = true;
        self.output_dir = output_dir.to_string();
    }

    pub async fn set_nats_options(
        &mut self,
        server: &str,
        node_id: &Option<String>,
        subject: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        // Validate node_id format if provided
        if let Some(ref id) = node_id {
            if !Self::is_valid_node_id(id) {
                return Err("Node ID must be 8 characters matching pattern [_a-zA-Z0-9]{8}".into());
            }
        }

        let client = async_nats::connect(server).await?;
        let jetstream = async_nats::jetstream::new(client);

        self.nats_enabled = true;
        self.jetstream = Some(jetstream);
        self.node_id = node_id.clone();
        self.subject = subject.to_string();

        println!("Connected to NATS server: {}", server);
        if let Some(ref id) = node_id {
            println!("Node ID: {}", id);
        }
        println!("Publishing to subject: {}", subject);

        Ok(())
    }

    fn is_valid_node_id(node_id: &str) -> bool {
        node_id.len() == 8 && node_id.chars().all(|c| c.is_alphanumeric() || c == '_')
    }

    pub async fn start_capture(&mut self) -> Result<(), Box<dyn std::error::Error>> {
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
                return Err(e.into());
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
                    return Err(e);
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

                    // Send to NATS if enabled
                    if self.nats_enabled {
                        if let Err(e) = self.send_to_nats(&packet_info).await {
                            eprintln!("Failed to send packet to NATS: {}", e);
                        }
                    }
                }
                Err(e) => {
                    eprintln!("Warning: {}", e);
                    continue;
                }
            }
        }
    }

    async fn send_to_nats(
        &self,
        packet_info: &PacketData,
    ) -> Result<(), Box<dyn std::error::Error>> {
        if let Some(ref jetstream) = self.jetstream {
            let payload = serde_json::to_vec(packet_info)?;
            let payload_bytes = Bytes::from(payload);

            let mut headers = HeaderMap::new();
            if let Some(ref node_id) = self.node_id {
                headers.insert("NodeID", node_id.as_str());
            }
            headers.insert("Interface", &self.interface);
            headers.insert("Timestamp", &packet_info.timestamp);

            let ack = jetstream
                .publish_with_headers(&self.subject, headers, payload_bytes)
                .await?;

            // Await acknowledgment
            ack.await?;
        }
        Ok(())
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

    fn parse_packet(&self, packet: &pcap::Packet) -> PacketData {
        let mut info = PacketData {
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
            raw_data: packet.data.to_vec(),
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

    fn display_packet(&self, info: &PacketData) {
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
