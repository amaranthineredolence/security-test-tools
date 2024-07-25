from scapy.all import *
import pandas as pd
import matplotlib.pyplot as plt
import logging

logging.basicConfig(filename='network_traffic_analyzer.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def analyze_traffic(packet):
    try:
        if packet.haslayer(IP):
            ip_src = packet[IP].src
            ip_dst = packet[IP].dst
            protocol = packet[IP].proto
            return (ip_src, ip_dst, protocol)
    except Exception as e:
        logging.error(f'Error analyzing traffic: {e}')

if __name__ == "__main__":
    try:
        logging.info('Starting network traffic analysis')
        packets = sniff(count=100)
        traffic_data = [analyze_traffic(pkt) for pkt in packets if analyze_traffic(pkt)]
        df = pd.DataFrame(traffic_data, columns=['Source', 'Destination', 'Protocol'])
        df['Protocol'].value_counts().plot(kind='bar')
        plt.show()
        logging.info("Traffic analysis complete. Check network_traffic_analyzer.log for details.")
    except Exception as e:
        logging.error(f'Error capturing traffic: {e}')
