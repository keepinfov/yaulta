use pcap::Device;

pub struct DeviceManager;

impl DeviceManager {
    pub fn list_devices() {
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
}
