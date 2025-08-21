import socket
import datetime
import struct
import ipaddress
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

def main():
    s = open_raw_ipv4_socket()
    print("[*] Sniffer running. Ctrl+C to stop.")
    try:
        while True:
            pkt = s.recvfrom(65535)[0]
            ts = datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3]

            hdr = parse_ipv4_header(pkt)
            if not hdr:
                print(f"[{ts}] len={len(pkt)} bytes  dump={hexdump(pkt)}")
                continue

            ihl_bytes, total_len, proto, src_ip, dst_ip = hdr
            # 1) filter (skip LAN to LAN and multicast)
            if (is_private(src_ip) and is_private(dst_ip)) or is_multicast(src_ip) or is_multicast(dst_ip):
                continue

            # 2) parse ports
            payload = pkt[ihl_bytes:]
            sport, dport = parse_ports(proto, payload)
            pname = PROTO_NAME.get(proto, str(proto))

            # 3) optional rDNS (after filter)
            if USE_RDNS:
                show_src = rdns(src_ip)
                show_dst = rdns(dst_ip)
                who_src = show_src if show_src != src_ip else src_ip
                who_dst = show_dst if show_dst != dst_ip else dst_ip
            else:
                who_src, who_dst = src_ip, dst_ip

            # 4) print
            if sport is not None:
                if proto == 6:  # TCP
                    flags = tcp_flags_str(payload)
                    extra = f" flags={flags}" if flags else ""
                    print(f"[{ts}] {who_src}:{sport} -> {who_dst}:{dport}  proto=TCP len={total_len}{extra}")
                else:
                    print(f"[{ts}] {who_src}:{sport} -> {who_dst}:{dport}  proto={pname} len={total_len}")
            else:
                print(f"[{ts}] {who_src} -> {who_dst}  proto={pname} len={total_len}")

    except KeyboardInterrupt:
        print("\n[!] Stopping...")
    finally:
        try:
            s.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
        except Exception:
            pass
        s.close()

if __name__ == "__main__":
    main()