from scapy.all import *
import pandas as pd
import logging

logging.basicConfig(filename='ids.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def packet_callback(packet):
    try:
        if packet.haslayer(IP):
            ip_src = packet[IP].src
            ip_dst = packet[IP].dst
            logging.info(f'Packet: {ip_src} -> {ip_dst}')
    except Exception as e:
        logging.error(f'Error processing packet: {e}')

if __name__ == "__main__":
    try:
        logging.info('Starting IDS')
        sniff(prn=packet_callback, store=0)
        print("Monitoring complete. Check ids.log for details.")
    except Exception as e:
        logging.error(f'Error starting IDS: {e}')
