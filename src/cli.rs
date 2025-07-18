use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "yaulta")]
#[command(about = "A simple, modern, and fast CLI tool to monitor network traffic in real-time", long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// List all available network interfaces
    List,
    /// Capture packets from a specific interface
    Capture {
        /// Name of the interface to capture from
        #[arg(short, long)]
        interface: String,
        /// Save captured packets to a pcap file
        #[arg(short, long)]
        save: bool,
        /// Output directory for saved pcap files (default: current directory)
        #[arg(short, long, default_value = ".")]
        output_dir: String,
        /// NATS server address (e.g., localhost:4222)
        #[arg(short, long)]
        nats_server: Option<String>,
        /// Node ID for NATS headers (8 characters: [_a-zA-Z0-9]{8})
        #[arg(short = 'n', long)]
        node_id: Option<String>,
        /// Subject for NATS JetStream publishing
        #[arg(long, default_value = "network.packets")]
        subject: String,
    },
}
