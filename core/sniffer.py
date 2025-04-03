from scapy.all import sniff
from detectors.basic_detector import detect

def packet_callback(packet):
    detect(packet)

def start_sniffing():
    sniff(prn=packet_callback, store=0)