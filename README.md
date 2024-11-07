
# Network Traffic Monitoring Tool

This project is a network traffic monitoring tool written in C, using the Packet Capture Library (`libpcap`). 
The tool is designed to capture and analyze network packets, extracting detailed information about TCP and UDP traffic.

## Overview

The tool captures packets from both:
1. A live network interface (e.g., `eth0`, `enp0s3` for VMs)
2. A saved `.pcap` file

Using `libpcap`, the tool processes packet data, identifying details such as source and destination IP addresses, 
source and destination ports, IP version, and protocol type (TCP or UDP).

## Libraries

- `libpcap`: Required for packet capturing. [Install instructions](https://www.tcpdump.org).
- `netinet`: Used for data structures representing ethernet frames and IP protocols.

## How It Works

### Live Capture

- **Function**: `online_monitor()`
- Sets `store_flag` to `1` and uses `pcap_loop()` to initiate real-time packet capture, triggering a callback function for each packet.
  
### File Capture

- **Function**: `offline_monitor()`
- Uses `pcap_loop()` to read packets from a `.pcap` file and extract packet information.

### Packet Handling

The `packet_handler()` function is called each time a packet is detected, extracting:
1. IP Version
2. Source & Destination IP Addresses
3. Source & Destination Ports
4. Protocol Type (TCP/UDP)

### TCP Retransmissions

UDP retransmissions aren't identifiable at the transport layer due to the connectionless nature of UDP (handled at the application layer). For TCP, retransmissions are detected using a linked list of network flows, which checks for retransmissions based on sequence information.

### Filter Mechanism

Instead of using `pcap_compile()` and `pcap_setfilter()`, custom filtering logic was added to `packet_handler()` to support the following filter expressions:

- `"ip version "`
- `"port "`
- `"ip "`
- `"protocol "`
- `"src port "`
- `"dst port "`
- `"src ip "`
- `"dst ip "`

To achieve this:
- **`checkSubstring()`**: Verifies if a substring contains a specific filter.
- **`parseFilter()`**: Parses user-provided filters and applies them to packet data.

## Compilation & Execution

### Compilation

Ensure that `libpcap-dev` is installed on your system. Then, use the following commands:

```bash
make          # Compiles the source code
make clean    # Removes the executable files
```

### Usage Examples

#### File Capture

To capture packets from a `.pcap` file:
```bash
./pcap_ex -r <filename>
```

#### Live Capture

To capture packets from a live network interface:
```bash
sudo ./pcap_ex -i eth0
sudo ./pcap_ex -i eth0 -f "src port 53"
```

Replace `eth0` with the relevant network interface name (e.g., `enp0s3` on VMs).

## References

- [Libpcap Documentation](https://linux.die.net/man/3/pcap)
- [TCPDump & Libpcap Homepage](https://www.tcpdump.org)
