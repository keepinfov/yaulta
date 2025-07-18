use clap::Parser;

mod cli;
mod device;
mod packet;

use cli::{Cli, Commands};
use device::DeviceManager;
use packet::PacketCapture;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    match &cli.command {
        Commands::List => {
            DeviceManager::list_devices();
        }
        Commands::Capture {
            interface,
            save,
            output_dir,
            nats_server,
            node_id,
            subject,
        } => {
            let mut capture = PacketCapture::new(interface).await?;

            if *save {
                capture.set_save_options(output_dir);
            }

            if let Some(server) = nats_server {
                capture.set_nats_options(server, node_id, subject).await?;
            }

            capture.start_capture().await?;
        }
    }

    Ok(())
}
