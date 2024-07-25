from scapy.all import *
import logging

logging.basicConfig(filename='packet_sniffer.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def packet_sniffer(packet):
    try:
        if packet.haslayer(IP):
            logging.info(packet.summary())
    except Exception as e:
        logging.error(f'Error capturing packet: {e}')

if __name__ == "__main__":
    try:
        logging.info('Starting packet sniffer')
        sniff(prn=packet_sniffer, store=0)
        print("Sniffing complete. Check packet_sniffer.log for details.")
    except Exception as e:
        logging.error(f'Error starting packet sniffer: {e}')
