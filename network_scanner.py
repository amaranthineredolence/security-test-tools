
import nmap
import logging
from datetime import datetime

logging.basicConfig(filename='network_scan.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def network_scan(ip_range):
    nm = nmap.PortScanner()
    try:
        logging.info(f'Starting scan on {ip_range}')
        nm.scan(hosts=ip_range, arguments='-p 1-65535 -sV')
        for host in nm.all_hosts():
            logging.info(f'Host: {host} ({nm[host].hostname()})')
            logging.info(f'State: {nm[host].state()}')
            for proto in nm[host].all_protocols():
                logging.info(f'Protocol: {proto}')
                ports = nm[host][proto].keys()
                for port in ports:
                    logging.info(f'Port: {port}\tState: {nm[host][proto][port]["state"]}\tService: {nm[host][proto][port]["name"]}')
    except Exception as e:
        logging.error(f'Error during scan: {e}')

if __name__ == "__main__":
    ip_range = input("Enter IP range to scan: ")
    network_scan(ip_range)
    print("Scan complete. Check network_scan.log for details.")
