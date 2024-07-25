import pandas as pd
import logging

logging.basicConfig(filename='firewall_rule_analyzer.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def analyze_firewall_rules(rules):
    try:
        logging.info('Starting firewall rule analysis')
        df = pd.DataFrame(rules)
        redundant_rules = df[df.duplicated()]
        if not redundant_rules.empty:
            logging.info("Redundant Rules:")
            logging.info(redundant_rules)
        else:
            logging.info("No redundant rules found.")
    except Exception as e:
        logging.error(f'Error analyzing firewall rules: {e}')

if __name__ == "__main__":
    firewall_rules = [
        {'source': 'any', 'destination': 'any', 'port': '80', 'action': 'allow'},
        {'source': 'any', 'destination': 'any', 'port': '80', 'action': 'allow'},
        {'source': '192.168.1.0/24', 'destination': 'any', 'port': '22', 'action': 'allow'}
    ]
    analyze_firewall_rules(firewall_rules)
    print("Analysis complete. Check firewall_rule_analyzer.log for details.")
