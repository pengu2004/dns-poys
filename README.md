# DNS Packet Sniffer — Real-time DNS Query Logger

DNS Packet Sniffer is a lightweight and efficient tool written in Python that captures and logs DNS queries and responses in real-time on macOS and Unix-like systems. It leverages low-level Berkeley Packet Filter (BPF) interfaces to directly access network packets on your specified network interface (e.g., `en0`).

This project is perfect for network engineers, security researchers, and enthusiasts who want to monitor DNS traffic, troubleshoot network issues, or detect suspicious activity on their local network.

## Features

- **Real-time DNS Monitoring**: Captures live DNS queries and responses (UDP port 53) on the specified network interface
- **Network Visibility**: Displays source and destination IPs for every DNS packet
- **Efficient Packet Capture**: Uses raw BPF device access for efficient packet capture without third-party dependencies
- **Lightweight**: Runs with minimal permissions and lightweight Python code
- **Extensible**: Easily extensible to parse DNS payloads and add advanced filtering or alerting

## Usage

1. **Run the script with root privileges:**
   ```bash
   sudo python3 server.py
   ```

2. **Configure the network interface** inside the script (default: `en0`)

3. **Monitor output** - The script will display DNS queries in real-time:
   ```
   DNS query #1 192.168.1.8 -> 218.248.112.181
   DNS query #2 218.248.112.181 -> 192.168.1.8
   DNS query #3 192.168.1.15 -> 8.8.8.8
   ...
   ```

## How It Works

1. **BPF Device Access**: Opens the BPF device `/dev/bpf*` and attaches it to the chosen network interface
2. **Real-time Capture**: Sets immediate mode for real-time packet capture
3. **Raw Packet Processing**: Reads raw packets from BPF buffer
4. **Protocol Parsing**: Parses Ethernet, IPv4, UDP headers to identify DNS packets (port 53)
5. **Logging**: Counts and logs DNS queries and responses with source/destination IP addresses

## Security & Permissions

- **Root Privileges Required**: Requires root privileges to open BPF devices and capture raw packets
- **Read-Only Monitoring**: Only listens on the specified interface; does not modify network traffic
- **Network Monitoring**: Code is read-only for network monitoring purposes only

## Requirements

- Python 3.x
- macOS or Unix-like operating system
- Root/sudo privileges
- Network interface access (e.g., `en0`, `eth0`)

## 🛠️ Installation

1. Clone this repository:
   ```bash
   git clone https://github.com/penu2004/dns-poys.git
   cd dns-poys
   ```

2. Make sure Python 3 is installed:
   ```bash
   python3 --version
   ```

3. Run the sniffer:
   ```bash
   sudo python3 server.py
   ```
4. Sample output:
```bash
Listening on en0 for UDP/53 traffic...
DNS query #1 192.168.1.8 -> 218.248.112.181
DNS query #2 218.248.112.181 -> 192.168.1.8
DNS query #3 192.168.1.8 -> 218.248.112.181
DNS query #4 192.168.1.8 -> 218.248.112.181
DNS query #5 218.248.112.181 -> 192.168.1.8
DNS query #6 218.248.112.181 -> 192.168.1.8
DNS query #7 192.168.1.8 -> 218.248.112.181
DNS query #8 218.248.112.181 -> 192.168.1.8
DNS query #9 192.168.1.8 -> 218.248.112.181
```
This project was inspired by the dns.toys project by Kailash Nadh(https://github.com/knadh/dns.toys)

**Note**: This tool requires root privileges and should be used responsibly and in accordance with your local laws and network policies.
