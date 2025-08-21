import socket
import datetime
import struct

PROTO_NAME = {1: "ICMP", 6: "TCP", 17: "UDP"}

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

def main():
    s = open_raw_ipv4_socket()
    print("[*] Sniffer running. Ctrl+C to stop.")
    try:
        while True:
            pkt = s.recvfrom(65535)[0]
            ts = datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3]

            hdr = parse_ipv4_header(pkt)
            if hdr:
                ihl_bytes, total_len, proto, src_ip, dst_ip = hdr
                payload = pkt[ihl_bytes:]
                sport, dport = parse_ports(proto, payload)
                pname = PROTO_NAME.get(proto, str(proto))
                if sport is not None:
                    print(f"[{ts}] {src_ip}:{sport} -> {dst_ip}:{dport}  proto={pname} len={total_len}")
                else:
                    print(f"[{ts}] {src_ip} -> {dst_ip}  proto={pname} len={total_len}")
            else:
                # fallback if something odd slips through
                print(f"[{ts}] len={len(pkt)} bytes  dump={hexdump(pkt)}")
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