## DAT Packet Sniffer

Python packet sniffer for Windows that captures IPv4 packets, parses headers, and provides live traffic summaries or aggregate statistics.

This project was built as a learning tool to explore raw sockets, packet parsing, and basic network analysis without relying on heavy external libraries.

---

## Features

- Captures raw IPv4 packets using Python sockets  
- Displays per-packet details:  
  - Source and destination IPs (with optional reverse DNS lookups)  
  - Protocol (TCP, UDP, ICMP, etc.)  
  - Ports (for TCP/UDP)  
  - TCP flags (SYN, ACK, FIN, etc.)  
- Filters out **RFC1918 (private)** and **multicast** chatter  
- **Stats mode**:  
  - Aggregates traffic by protocol, source, destination, and ports  
  - Tracks TCP flag usage  
  - Outputs periodic or final snapshots  
  - Human-readable byte totals (e.g., `4.25 MB`)  
- **Logging**:  
  - Write to console, logfile, or both  
  - `--no-console` disables console output  
  - Logfile directories are created automatically  
- Works entirely in Python’s standard library (no external deps)  

---

## Requirements

Python 3.11+

Windows with administrator privileges (raw sockets required)

---

## Usage

Clone the repo and run:

python main.py

---

Per-packet mode (default)

Shows live packet flow with IPs, ports, and flags:

[16:59:17.293] 10.2.0.2:32414 -> 142.251.214.142:443  proto=TCP len=144 flags=ACK  
[16:59:18.540] MyPC -> 151.101.41.91:443           proto=TCP len=40 flags=FIN,ACK  

---

Stats mode

Aggregate stats instead of per-packet logs:

python main.py --stats --interval 10

Example:

=== Stats Snapshot ===

Total: pkts=151  bytes=25,687 (25.08 KB)

By protocol:  
  proto   |    count   
  UDP     |    132  
  TCP     |    19  

Top sources:  
  MyPC           90  
  162-254-193-98   70  

Top destinations:  
  104.29.158.102   61  
  104.29.158.105   53  

TCP flags:  
  ACK             19  
  SYN              1   

---

Useful flags

--stats : Enable statistics mode

--interval N : Print stats snapshot every N seconds (default 10; 0 = final only)

--top N : Show top N items in each table (default 10)

--no-rdns : Disable reverse DNS lookups

--logfile FILE : Append output to logfile (UTF-8)

--no-console : Suppress console output (logfile only)

---

## Learning Goals

This project demonstrates:

Using raw sockets for packet capture

Parsing IPv4 and TCP/UDP headers with struct

Efficient aggregation with collections.Counter

Applying filters (RFC1918, multicast) to reduce noise

Formatting output for readability

---

## Next Steps

Add JSON export for stats

Extend parsing to IPv6

Add basic protocol decoding (HTTP, DNS, etc.)

Support Linux/macOS capture

---

## Disclaimer

This project is for educational use only. Running a packet sniffer may require permission depending on your environment. Always ensure you comply with your local laws and network policies.
