import socket
import time
import datetime
import struct
import ipaddress
import argparse
from collections import Counter
from functools import lru_cache

USE_RDNS = True

PROTO_NAME = {1: "ICMP", 6: "TCP", 17: "UDP"}

PRIVATE_NETS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
]
MULTICAST_NET = ipaddress.ip_network("224.0.0.0/4")  # includes 239.255.255.250

def is_private(ip: str) -> bool:
    ipobj = ipaddress.ip_address(ip)
    return any(ipobj in net for net in PRIVATE_NETS)

def is_multicast(ip: str) -> bool:
    return ipaddress.ip_address(ip) in MULTICAST_NET

@lru_cache(maxsize=1024)
def rdns(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ip  # fallback to IP if no PTR

def parse_ipv4_header(data: bytes):
    if len(data) < 20:
        return None
    v_ihl = data[0]
    version = v_ihl >> 4
    ihl = v_ihl & 0x0F
    if version != 4 or ihl < 5:
        return None
    ihl_bytes = ihl * 4
    _, _, total_len, _, _, _, proto, _, src, dst = struct.unpack('!BBHHHBBH4s4s', data[:20]) # !BBHHHBBH4s4s  = IPv4 fixed header
    src_ip = ".".join(map(str, src))
    dst_ip = ".".join(map(str, dst))
    return ihl_bytes, total_len, proto, src_ip, dst_ip

def parse_ports(proto: int, payload: bytes):
    if proto not in (6, 17) or len(payload) < 4:
        return None, None
    sport, dport = struct.unpack("!HH", payload[:4])
    return sport, dport

def hexdump(data: bytes, max_bytes: int = 64) -> str:
    data = data[:max_bytes]
    return " ".join(f"{b:02x}" for b in data)

def _get_default_iface_ip() -> str:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80)) 
        ip = s.getsockname()[0]
    finally:
        s.close()
    return ip

def open_raw_ipv4_socket():
    host_ip = _get_default_iface_ip()
    print(f"[*] Binding raw socket to {host_ip}")

    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
    # MUST be a real local IP on Windows
    s.bind((host_ip, 0))
    s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    # Enable promiscuous mode on that interface
    s.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
    return s

def tcp_flags_str(payload: bytes) -> str:
    if len(payload) < 20:
        return ""
    # data offset (upper 4 bits of byte 12) tells header size if you want later
    flags = payload[13]
    # bit order (from MSB to LSB): CWR ECE URG ACK PSH RST SYN FIN
    names = ["CWR","ECE","URG","ACK","PSH","RST","SYN","FIN"]
    return ",".join(n for bit, n in enumerate(names[::-1]) if flags & (1 << bit))

def human_bytes(n: int) -> str:
    """e.g., 4443318 -> '4.24 MB'"""
    units = ["B","KB","MB","GB","TB"]
    f = float(n)
    for u in units:
        if f < 1024 or u == units[-1]:
            return f"{f:.2f} {u}"
        f /= 1024

def _truncate(s: str, width: int) -> str:
    return s if len(s) <= width else s[: max(0, width-1)] + "…"

def counter_table(counter, title: str, key_label: str, top_n=10,
                  key_width=36, val_width=8) -> str:
    if not counter:
        return f"{title}:\n  (none)\n"
    rows = []
    header = f"{title}:\n  {key_label.ljust(key_width)} {'count'.rjust(val_width)}"
    underline = "  " + "-"*key_width + " " + "-"*val_width
    rows.append(header)
    rows.append(underline)
    for key, val in counter.most_common(top_n):
        rows.append(f"  {_truncate(str(key), key_width).ljust(key_width)} {str(val).rjust(val_width)}")
    return "\n".join(rows) + "\n"

class Stats:
    def __init__(self):
        self.pkts = 0
        self.bytes = 0
        self.by_proto = Counter()
        self.src = Counter()
        self.dst = Counter()
        self.sport = Counter()
        self.dport = Counter()
        self.tcp_flags = Counter()

    def update(self, *, length: int, proto: str, src: str, dst: str,
               sport: int | None, dport: int | None, flags: str | None):
        self.pkts += 1
        self.bytes += int(length)
        self.by_proto[proto] += 1
        self.src[src] += 1
        self.dst[dst] += 1
        if sport is not None: self.sport[sport] += 1
        if dport is not None: self.dport[dport] += 1
        if flags:
            for f in flags.split(","):
                self.tcp_flags[f] += 1

    def snapshot(self, top_n=10) -> str:
        lines = []
        lines.append("=== Stats Snapshot ===")
        lines.append(f"Total: pkts={self.pkts:,}  bytes={self.bytes:,} ({human_bytes(self.bytes)})\n")

        lines.append(counter_table(self.by_proto, "By protocol", "proto", top_n, key_width=10, val_width=10))
        lines.append(counter_table(self.src,      "Top sources", "source", top_n))
        lines.append(counter_table(self.dst,      "Top destinations", "destination", top_n))
        lines.append(counter_table(self.sport,    "Top source ports", "sport", top_n, key_width=10))
        lines.append(counter_table(self.dport,    "Top destination ports", "dport", top_n, key_width=10))

        if self.tcp_flags:
            lines.append(counter_table(self.tcp_flags, "TCP flags", "flag", top_n, key_width=10))

        lines.append("======================")
        return "\n".join(lines)

def parse_args():
    p = argparse.ArgumentParser(description="DAT Packet Sniffer")
    p.add_argument("--stats", action="store_true",
                   help="Aggregate and print stats instead of per-packet lines.")
    p.add_argument("--interval", type=int, default=10,
                   help="Stats snapshot interval in seconds (0 = only final on exit).")
    p.add_argument("--top", type=int, default=10,
                   help="How many top items to show in each list.")
    p.add_argument("--no-rdns", action="store_true",
                   help="Disable reverse DNS lookups.")
    p.add_argument("--logfile", type=str,
                   help="Append output to this file (UTF-8).")
    p.add_argument("--no-console", action="store_true",
                   help="Do not print to console (logfile only).")
    return p.parse_args()

class Tee:
    def __init__(self, path: str | None, to_console: bool = True):
        self.to_console = to_console
        self.fh = None
        if path:
            try:
                # ensure parent dir exists
                from pathlib import Path
                Path(path).expanduser().resolve().parent.mkdir(parents=True, exist_ok=True)
                self.fh = open(path, "a", encoding="utf-8")
            except Exception as e:
                print(f"[WARN] Could not open logfile '{path}': {e}")
                self.fh = None

    def write(self, line: str):
        if self.to_console:
            print(line)
        if self.fh:
            self.fh.write(line + "\n")
            self.fh.flush()

    def close(self):
        if self.fh:
            self.fh.close()

def main():
    s = open_raw_ipv4_socket()
    out = Tee(ARGS.logfile, to_console=not ARGS.no_console)
    out.write("[*] Sniffer running. Ctrl+C to stop.")
    if ARGS.logfile:
        out.write(f"[*] Logging to: {ARGS.logfile}  (console={'off' if ARGS.no_console else 'on'})")
    out.write(f"[*] rDNS: {'on' if (not ARGS.no_rdns) else 'off'}")
    stats = Stats()
    last = time.monotonic()
    try:
        while True:
            pkt = s.recvfrom(65535)[0]
            ts = datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3]

            hdr = parse_ipv4_header(pkt)
            if not hdr:
                if not ARGS.stats:
                    out.write(f"[{ts}] len={len(pkt)} bytes  dump={hexdump(pkt)}")
                continue

            ihl_bytes, total_len, proto_num, src_ip, dst_ip = hdr
            if (is_private(src_ip) and is_private(dst_ip)) or is_multicast(src_ip) or is_multicast(dst_ip):
                continue

            payload = pkt[ihl_bytes:]
            sport, dport = parse_ports(proto_num, payload)
            pname = PROTO_NAME.get(proto_num, str(proto_num))

            who_src, who_dst = src_ip, dst_ip
            if USE_RDNS:
                show_src = rdns(src_ip)
                show_dst = rdns(dst_ip)
                who_src = show_src if show_src != src_ip else src_ip
                who_dst = show_dst if show_dst != dst_ip else dst_ip

            flags = None
            if proto_num == 6:
                flags = tcp_flags_str(payload)

            if ARGS.stats:
                stats.update(length=total_len, proto=pname, src=who_src, dst=who_dst,
                             sport=sport, dport=dport, flags=flags)
                if ARGS.interval and (time.monotonic() - last) >= ARGS.interval:
                    out.write("")  # blank line
                    out.write("=== Stats Snapshot ===")
                    out.write(stats.snapshot(top_n=ARGS.top))
                    out.write("======================")
                    out.write("")
                    last = time.monotonic()
            else:
                if sport is not None:
                    if proto_num == 6 and flags:
                        out.write(
                            f"[{ts}] {who_src}:{sport} -> {who_dst}:{dport}  proto=TCP len={total_len} flags={flags}")
                    else:
                        out.write(f"[{ts}] {who_src}:{sport} -> {who_dst}:{dport}  proto={pname} len={total_len}")
                else:
                    out.write(f"[{ts}] {who_src} -> {who_dst}  proto={pname} len={total_len}")

    except KeyboardInterrupt:
        out.write("\n[!] Stopping...")
    finally:
        try:
            s.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
        except Exception:
            pass
        s.close()
        if ARGS.stats:
            out.write("\n=== Final Stats ===")
            out.write(stats.snapshot(top_n=ARGS.top))
            out.write("===================\n")
        out.close()

if __name__ == "__main__":
    ARGS = parse_args()
    USE_RDNS = not ARGS.no_rdns
    main()