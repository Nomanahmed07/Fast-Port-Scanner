# Fast Port Scanner

A professional, multi-threaded network reconnaissance tool written in Python. This script leverages the native `socket` library and `concurrent.futures` to rapidly discover active hosts and perform detailed port auditing across targeted subnets or individual IP addresses.

## Features
- **Optimized Host Discovery:** Multi-threaded discovery sweep using low-overhead sockets.
- **Flexible Scope Parsing:** Supports single IPs, continuous ranges (e.g., `192.168.1.1-50`), and full CIDR subnets (e.g., `192.168.1.0/24`).
- **Comprehensive Auditing:** Features targeted VIP administrative ports, top threat profile lists, and full 1-65535 range scans.
- **Banner Grabbing & OS Fingerprinting:** Extracts basic service banners and performs SMB-based OS fingerprinting for Windows/Linux nodes.
- **Dual Format Logging:** Automatically exports detailed plain-text logs (`.txt`) and structured payloads (`.json`) upon completion.

## Installation & Usage

Ensure you have Python 3.x installed. No external dependencies are required.

```bash
# Clone the repository
git clone [https://github.com/Nomanahmed07/Fast-Port-Scanner.git](https://github.com/Nomanahmed07/Fast-Port-Scanner.git)

# Navigate into the directory
cd Fast-Port-Scanner

# Run the application
python3 fast_port_scanner.py
