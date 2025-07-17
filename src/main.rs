use clap::Parser;

mod cli;
mod device;
mod packet;

use cli::{Cli, Commands};
use device::DeviceManager;
use packet::PacketCapture;

fn main() {
    let cli = Cli::parse();

    match &cli.command {
        Commands::List => {
            DeviceManager::list_devices();
        }
        Commands::Capture { interface } => {
            let mut capture = PacketCapture::new(interface);
            capture.start_capture();
        }
    }
}
