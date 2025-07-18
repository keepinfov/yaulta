# Usage Examples

## Basic packet capture (display only)
```bash
yaulta capture -i eth0
```

## Save packets to pcap file in current directory
```bash
yaulta capture -i eth0 -s
```
This will create a file like `dump_20250718_143022.pcap` in the current directory.

## Save packets to pcap file in specific directory
```bash
yaulta capture -i eth0 -s -o /path/to/captures
```
This will create a file like `/path/to/captures/dump_20250718_143022.pcap`.

## Send packets to NATS JetStream
```bash
yaulta capture -i eth0 --nats-server localhost:4222 --node-id NODE_001
```

## Send packets to NATS with custom subject
```bash
yaulta capture -i eth0 --nats-server localhost:4222 --node-id NODE_001 --subject network.traffic
```

## Capture, save to file, and send to NATS
```bash
yaulta capture -i eth0 -s -o /captures --nats-server localhost:4222 --node-id NODE_001
```

## List available interfaces
```bash
yaulta list
```

## Command line options
- `-i, --interface <INTERFACE>`: Network interface to capture from
- `-s, --save`: Save captured packets to a pcap file
- `-o, --output-dir <OUTPUT_DIR>`: Directory to save pcap files (default: current directory)
- `--nats-server <SERVER>`: NATS server address (e.g., localhost:4222)
- `-n, --node-id <NODE_ID>`: Node ID for NATS headers (8 characters: [_a-zA-Z0-9]{8})
- `--subject <SUBJECT>`: Subject for NATS JetStream publishing (default: network.packets)

## NATS Integration Details

### Message Format
Packets are published as JSON with the following structure:
```json
{
  "timestamp": "2025/07/18 14:30:22 +02:00",
  "protocol": "tcp",
  "src_ip": "192.168.1.100",
  "dst_ip": "8.8.8.8",
  "dst_port": 443,
  "bytes": 1500,
  "ip_protocol": "tcp",
  "data_bytes": 1460,
  "raw_data": [/* binary packet data as byte array */]
}
```

### Headers
Each message includes headers:
- `NodeID`: The node identifier (if specified)
- `Interface`: The network interface name
- `Timestamp`: When the packet was captured

### Node ID Format
Node ID must be exactly 8 characters matching pattern `[_a-zA-Z0-9]{8}`:
- Valid: `NODE_001`, `SERVER01`, `EDGE_ABC`, `12345678`
- Invalid: `node1` (too short), `NODE-001` (contains hyphen), `VERYLONGNAME` (too long)

### Acknowledgments
The tool waits for acknowledgment from NATS JetStream for each published packet to ensure delivery.

## File naming convention
Saved pcap files follow the format: `dump_<YYYYMMDD>_<HHMMSS>.pcap`
- Example: `dump_20250718_143022.pcap`
