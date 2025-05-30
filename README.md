# 🚦 rudeus

[![Rust](https://img.shields.io/badge/Rust-orange?logo=rust)](https://www.rust-lang.org/) [![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux-blue)](#requirements) [![License](https://img.shields.io/badge/License-MIT-green)](LICENSE)

**rudeus** is a simple, modern, and fast CLI tool to monitor network traffic in real-time. It's a lightweight alternative to Wireshark/npCap, built with Rust, and works on both Windows and Linux.

---

## ✨ Features
- 🔎 **List all network interfaces** (with friendly name/description if available)
- 📡 **Real-time packet capture** from a selected interface
- 👁️ **Human-readable output**: IP source/destination, protocol, port, and payload preview
- 🌐 **HTTP request/URL parsing** for HTTP traffic (GET/POST etc. on port 80/8080/8000)
- ⚡ **Cross-platform**: Windows (Npcap/WinPcap) & Linux (libpcap)

---

## 🛠️ Requirements
- [Rust](https://rustup.rs)
- WinPcap/Npcap (for Windows, if not already installed)
- libpcap (for Linux, usually pre-installed or available via package manager)

---

## 🚀 Usage

### 1. List network interfaces
```bash
cargo run -- list
```
**Example output:**
```
Available interfaces:
- \Device\NPF_{GUID1} (Intel(R) Ethernet Connection)
- \Device\NPF_{GUID2} (Wi-Fi)
- \Device\NPF_Loopback (Adapter for loopback traffic capture)
```

### 2. Capture traffic on a specific interface
```bash
cargo run -- capture -i <interface_name>
```
Replace `<interface_name>` with the name from the list above.

**Example output:**
```
[Packet #1] 81 bytes
Link: Ethernet2(...)
IPv4: 192.168.1.10 -> 8.8.8.8
Protocol: 6
TCP: 54321 -> 443
Flags: SYN=true ACK=false FIN=false RST=false
Seq: 123456, Window: 65535
Payload: 0 bytes
Payload: empty

[Packet #2] 120 bytes
...
HTTP Request: GET /index.html
Host: example.com
```

---

## 📝 Notes
- Press `Ctrl+C` to stop capturing
- Run as **Administrator** (Windows) or with `sudo` (Linux) if you get permission errors
- Only a summary of each packet is shown (not full protocol decode)
- HTTP request/URL parsing is shown for HTTP traffic on common ports
- Some non-IP or malformed packets may be skipped for readability

---

## 💡 Extend rudeus
Feel free to extend this tool for deeper protocol analysis, filtering, or saving to PCAP files!

---

> Made with ❤️ using Rust — Happy sniffing! 