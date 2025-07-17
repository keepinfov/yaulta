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
    },
}
