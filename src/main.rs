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
        Commands::Capture {
            interface,
            save,
            output_dir,
        } => {
            let mut capture = PacketCapture::new(interface);
            if *save {
                capture.set_save_options(output_dir);
            }
            capture.start_capture();
        }
    }
}
