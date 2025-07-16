# Yaulta

Yaulta is a modern, fast, and cross-platform CLI tool for real-time network traffic monitoring—think Wireshark, but in your terminal. Built with Rust, it works seamlessly on both Windows and Linux.

## 📚 Library Requirements

- **Windows:** Download and install [Npcap SDK](https://npcap.com/#download)
- **Debian/Ubuntu:**
  ```sh
  sudo apt install libpcap-dev
  ```
- **Fedora:**
  ```sh
  sudo dnf install libpcap-devel
  ```

## ✨ Features
- List all available network interfaces
- Real-time packet capture from any interface
- HTTP/HTTPS detection and parsing on all ports
- Clean, table-like single-line output per packet:
  ```
  tcp | 192.168.1.3 | 34.101.169.118  | 2025/05/31 02:21:54 +07:00 | 8441     | 400   | tcp         | 346
  ```
- Resilient: keeps running even on minor capture errors (only stops with CTRL+C)
- Cross-platform: Windows & Linux

## 🚀 Installation & Build

1. Make sure you have Rust installed. If not, get it from https://rustup.rs
2. Clone this repository:
   ```sh
   git clone <repo-url>
   cd yaulta
   ```
3. Build the application:
   ```sh
   cargo build --release
   ```
4. Run the application:
   ```sh
   cargo run --release -- capture --interface <interface_name>
   ```
   To list available interfaces:
   ```sh
   cargo run --release -- list
   ```

## 📦 Example Output
```
tcp | 192.168.1.3 | 34.101.169.118  | 2025/05/31 02:21:54 +07:00 | 8441     | 400   | tcp         | 346
udp | 192.168.1.3 | 34.101.169.119  | 2025/05/31 02:21:55 +07:00 | 53       | 120   | udp         | 80
```

## 📝 License

See the LICENSE file for details.

---

Made with ❤️ in Rust — Happy sniffing! 
