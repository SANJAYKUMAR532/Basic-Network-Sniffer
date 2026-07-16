import socket
import struct
import datetime
import sys
 
 
WELL_KNOWN_PORTS = {
    20: "FTP-DATA", 21: "FTP", 22: "SSH", 23: "TELNET", 25: "SMTP",
    53: "DNS", 67: "DHCP", 68: "DHCP", 80: "HTTP", 110: "POP3",
    123: "NTP", 143: "IMAP", 443: "HTTPS", 445: "SMB", 3306: "MySQL",
    3389: "RDP", 5432: "PostgreSQL", 8080: "HTTP-ALT",
}
 
PROTO_NAMES = {1: "ICMP", 6: "TCP", 17: "UDP"}
 
 
def guess_service(port):
    return WELL_KNOWN_PORTS.get(port, "")
 
 
def format_payload(raw_bytes, max_len=120):
    if not raw_bytes:
        return ""
    snippet = raw_bytes[:max_len]
    try:
        text = snippet.decode("utf-8")
        return "".join(c if c.isprintable() or c in "\r\n\t" else "." for c in text)
    except UnicodeDecodeError:
        return snippet.hex(" ")
 
 
def get_local_ip():
    """Find the primary local IP address (needed to bind the raw socket)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
    except Exception:
        ip = socket.gethostbyname(socket.gethostname())
    finally:
        s.close()
    return ip
 
 
def parse_ip_header(data):
    """Unpack the 20-byte IPv4 header."""
    ip_header = data[:20]
    unpacked = struct.unpack("!BBHHHBBH4s4s", ip_header)
 
    version_ihl = unpacked[0]
    ihl = (version_ihl & 0xF) * 4  # header length in bytes
    ttl = unpacked[5]
    protocol_num = unpacked[6]
    src_ip = socket.inet_ntoa(unpacked[8])
    dst_ip = socket.inet_ntoa(unpacked[9])
 
    return {
        "ihl": ihl,
        "ttl": ttl,
        "protocol_num": protocol_num,
        "protocol": PROTO_NAMES.get(protocol_num, f"OTHER({protocol_num})"),
        "src_ip": src_ip,
        "dst_ip": dst_ip,
    }
 
 
def parse_tcp_header(data, offset):
    tcp_header = data[offset:offset + 20]
    if len(tcp_header) < 20:
        return None, offset
    unpacked = struct.unpack("!HHLLBBHHH", tcp_header)
    sport, dport = unpacked[0], unpacked[1]
    data_offset = (unpacked[4] >> 4) * 4
    flags_byte = unpacked[5]
    flag_names = []
    for bit, name in [(0x01, "FIN"), (0x02, "SYN"), (0x04, "RST"),
                       (0x08, "PSH"), (0x10, "ACK"), (0x20, "URG")]:
        if flags_byte & bit:
            flag_names.append(name)
    payload_start = offset + data_offset
    return {
        "sport": sport, "dport": dport, "flags": "|".join(flag_names) or "-",
        "payload": data[payload_start:]
    }, payload_start
 
 
def parse_udp_header(data, offset):
    udp_header = data[offset:offset + 8]
    if len(udp_header) < 8:
        return None
    sport, dport, length, checksum = struct.unpack("!HHHH", udp_header)
    payload_start = offset + 8
    return {"sport": sport, "dport": dport, "payload": data[payload_start:]}
 
 
def parse_icmp_header(data, offset):
    icmp_header = data[offset:offset + 4]
    if len(icmp_header) < 4:
        return None
    icmp_type, code, checksum = struct.unpack("!BBH", icmp_header)
    return {"type": icmp_type, "code": code}
 
 
class PacketStats:
    def __init__(self):
        self.total = 0
        self.by_protocol = {}
 
    def record(self, proto):
        self.total += 1
        self.by_protocol[proto] = self.by_protocol.get(proto, 0) + 1
 
    def summary(self):
        lines = [f"\n{'='*50}", f"Capture summary: {self.total} packets", "-" * 50]
        for proto, count in sorted(self.by_protocol.items(), key=lambda x: -x[1]):
            lines.append(f"  {proto:<8} {count}")
        lines.append("=" * 50)
        return "\n".join(lines)
 
 
def main():
    if not sys.platform.startswith("win"):
        print("[!] This raw-socket version is written for Windows.")
        print("    On Linux/macOS, run this script with sudo instead — raw sockets")
        print("    work natively there without any extra driver.")
        sys.exit(1)
 
    host = get_local_ip()
    print(f"Local IP detected: {host}")
    print("Starting capture (no Npcap needed)... Press Ctrl+C to stop.")
    print("-" * 50)
 
    stats = PacketStats()
 
    try:
        sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
    except PermissionError:
        print("\n[!] Permission denied.")
        print("    Right-click PowerShell/CMD and choose 'Run as administrator', then try again.")
        sys.exit(1)
    except OSError as e:
        print(f"\n[!] Could not create raw socket: {e}")
        print("    Make sure you're running this terminal as Administrator.")
        sys.exit(1)
 
    sniffer.bind((host, 0))
    sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
 
    try:
        while True:
            raw_data, addr = sniffer.recvfrom(65535)
            timestamp = datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3]
 
            ip_info = parse_ip_header(raw_data)
            offset = ip_info["ihl"]
            proto = ip_info["protocol"]
            src_ip, dst_ip, ttl = ip_info["src_ip"], ip_info["dst_ip"], ip_info["ttl"]
 
            detail = f"{src_ip} -> {dst_ip}"
            payload = b""
 
            if ip_info["protocol_num"] == 6:  # TCP
                tcp_info, payload_start = parse_tcp_header(raw_data, offset)
                if tcp_info:
                    svc = guess_service(tcp_info["dport"]) or guess_service(tcp_info["sport"])
                    detail = (f"{src_ip}:{tcp_info['sport']} -> {dst_ip}:{tcp_info['dport']}"
                               f"  [flags={tcp_info['flags']}]")
                    if svc:
                        detail += f"  (service: {svc})"
                    payload = tcp_info["payload"]
 
            elif ip_info["protocol_num"] == 17:  # UDP
                udp_info = parse_udp_header(raw_data, offset)
                if udp_info:
                    svc = guess_service(udp_info["dport"]) or guess_service(udp_info["sport"])
                    detail = f"{src_ip}:{udp_info['sport']} -> {dst_ip}:{udp_info['dport']}"
                    if svc:
                        detail += f"  (service: {svc})"
                    payload = udp_info["payload"]
 
            elif ip_info["protocol_num"] == 1:  # ICMP
                icmp_info = parse_icmp_header(raw_data, offset)
                if icmp_info:
                    detail = f"{src_ip} -> {dst_ip}  [type={icmp_info['type']} code={icmp_info['code']}]"
 
            stats.record(proto)
            print(f"[{timestamp}] {proto:<5} {detail}  (ttl={ttl}, len={len(raw_data)})")
 
            if payload:
                print(f"            payload: {format_payload(payload)}")
 
    except KeyboardInterrupt:
        pass
    finally:
        sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
        sniffer.close()
        print(stats.summary())
 
 
if __name__ == "__main__":
    main()