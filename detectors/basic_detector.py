from scapy.layers.inet import IP, TCP

def detect(packet):
    if packet.haslayer(IP) and packet.haslayer(TCP):
        src_ip = packet[IP].src
        dst_port = packet[TCP].dport

        print(f"[+] Packet from {src_ip} to port {dst_port}")
        if dst_port in [21, 22, 23, 80, 443]:
            print(f"[!] Suspicious port access detected from {src_ip} to port {dst_port}")
            log_suspicious_activity(src_ip, dst_port)

def log_suspicious_activity(ip, port):
    with open("logs/alerts.log", "a") as log_file:
        log_file.write(f"ALERT: {ip} accessed suspicious port {port}\n")