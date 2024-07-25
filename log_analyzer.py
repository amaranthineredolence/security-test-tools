import pandas as pd
import logging

logging.basicConfig(filename='log_analyzer.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def analyze_logs(log_file):
    try:
        logging.info(f'Starting log analysis on {log_file}')
        df = pd.read_csv(log_file)
        df['timestamp'] = pd.to_datetime(df['timestamp'])
        df.set_index('timestamp', inplace=True)
        anomalies = df[df['event'] == 'suspicious']
        logging.info("Anomalies:")
        logging.info(anomalies)
    except Exception as e:
        logging.error(f'Error analyzing logs: {e}')

if __name__ == "__main__":
    log_file = input("Enter path to log file: ")
    analyze_logs(log_file)
    print("Log analysis complete. Check log_analyzer.log for details.")
