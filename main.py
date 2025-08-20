import socket
import datetime

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