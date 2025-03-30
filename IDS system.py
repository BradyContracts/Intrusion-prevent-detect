import subprocess
import sys
import time
import logging
import os
import shutil
import glob
import json
import psutil
import netifaces
import subprocess
import shlex
import boto3
import botocore
import botocore.exceptions
import botocore.client
import botocore.config
import boto3.session
import requests
import csv
import os
import re
import socket
import subprocess
import sys
import time
import traceback
import uuid
from collections import OrderedDict
from pathlib import Path
from subprocess import PIPE, Popen
from typing import List, Tuple, Union
import pickle
import pprint
import ipaddress
import collections
import collections.abc
import nltk
import spacy
from nltk.corpus import stopwords
from nltk.stem import WordNetLemmatizer
from nltk.tokenize import word_tokenize
from nltk.stem.porter import PorterStemmer
from nltk.stem.wordnet import WordNetLemmatizer
from nltk.corpus import wordnet
from nltk.stem.snowball import SnowballStemmer
import random
import re
import shutil
import subprocess
import sys
import time
import traceback
import uuid
import os
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders
import email
import requests

# Step 1: Read the requirements.txt file
def get_project_dependencies(file_path='requirements.txt'):
  """
  This function reads the requirements.txt file and returns a list of packages and their versions.

  Args:
    file_path (str): The path to the requirements.txt file.
    
  Returns:
    A list of packages and their versions.

    Example:
    >>> get_project_dependencies()
    [('requests', '2.18.4'), ('beautifulsoup4', '4.9.3'), ('lxml', '4.5.0'), ('numpy', '1.18.5'), ('pandas', '1.3.2'), ('scikit-learn', '0.20.3'), ('scipy', '1.4.1'), ('seaborn', '0.9.0'), ('matplotlib', '3.4.3'), ('plotly', '4.9.0'), ('tqdm', '4.62.3'), ('tensorflow', '2.6.0'), ('tensorflow-hub', '0.7.0'), ('tensorflow-text', '0.7.0'), ('tensorflow-gpu', '2.6.0'), ('tensorflow-datasets', '0.3.1'), ('tensorflow-probability', '0.9.0'), ('tensorflow-addons', '0.9.0'), ('tensorflow-datasets-nightly', '0.9.0'), ('tensorflow-hub-nightly', '0.9.0'), ('tensorflow-text-nightly', '0.9.0'), ('tensorflow-probability-nightly', '0.9.0'), ('tensorflow-addons-nightly', '0.9.0'), ('tensorflow-datasets-nightly', '0.9.0'), ('tensorflow-hub-nightly', '0.9.0'), ('tensorflow-text-nightly', '0.9.0'), ('tensorflow-probability-nightly', '0.9.0'), ('tensorflow-addons-nightly', '0.9.0')]

      with open(file_path, 'r') as file:
        dependencies = [line.strip() for line in file.readlines()]
    return dependencies

# Step 2: Check for vulnerabilities using an API
def check_vulnerabilities(dependencies):
    vulnerabilities = []
    for dependency in dependencies:
        response = requests.get(f'https://vulnerability_checker_api.com/{dependency}')
        if response.status_code == 200:
            vulnerability_data = response.json()
            if vulnerability_data['is_vulnerable']:
                vulnerabilities.append(vulnerability_data)
    return vulnerabilities

# Step 3: Report the found vulnerabilities
def report_vulnerabilities(vulnerabilities):
    print("Known Vulnerabilities Report:")
    for vulnerability in vulnerabilities:
        print(f"Package: {vulnerability['package']}")
        print(f"Current Version: {vulnerability['current_version']}")
        print(f"Vulnerable Versions: {vulnerability['vulnerable_versions']}")
        print(f"Fixed in Version: {vulnerability['fixed_in_version']}")
        print(f"Description: {vulnerability['description']}")
        print("-" * 50)
    

# Main function to run the vulnerability check
def main():
    dependencies = get_project_dependencies()
    vulnerabilities = check_vulnerabilities(dependencies)
    report_vulnerabilities(vulnerabilities)

if __name__ == "__main__":
    main()
# Step 4: Install the vulnerable packages
def install_vulnerable_packages(vulnerabilities):
    for vulnerability in vulnerabilities:
        package = vulnerability['package']
        current_version = vulnerability['current_version']
        vulnerable_versions = vulnerability['vulnerable_versions']
        fixed_in_version = vulnerability['fixed_in_version']
        description = vulnerability['description']
        print(f"Installing {package} version {fixed_in_version} to resolve the vulnerability.")
        # Install the vulnerable package
        # Step 5: Install the vulnerable packages
def install_vulnerable_packages(vulnerabilities):
    for vulnerability in vulnerabilities:
        package = vulnerability['package']
        current_version = vulnerability['current_version']
        vulnerable_versions = vulnerability['vulnerable_versions']
        fixed_in_version = vulnerability['fixed_in_version']
        description = vulnerability['description']
      
        print(f"Installing {package} version {fixed_in_version} to resolve the vulnerability.")
      
        # Install the vulnerable package
        # Step 6: Install the vulnerable packages
def install_vulnerable_packages(vulnerabilities):
    for vulnerability in vulnerabilities:
        package = vulnerability['package']
        current_version = vulnerability['current_version']
        vulnerable_versions = vulnerability['vulnerable_versions']
        fixed_in_version = vulnerability['fixed_in_version']
        description = vulnerability['description']
      
        print(f"Installing {package} version {fixed_in_version} to resolve the vulnerability.")
      
        # Install the vulnerable package
        # Step 7: Install the vulnerable packages
def install_vulnerable_packages(vulnerabilities):
    for vulnerability in vulnerabilities:
        package = vulnerability['package']
        current_version = vulnerability['current_version']
        vulnerable_versions = vulnerability['vulnerable_versions']
        fixed_in_version = vulnerability['fixed_in_version']
        description = vulnerability['description']
      
        print(f"Installing {package} version {fixed_in_version} to resolve the vulnerability.")
      
        # Install the vulnerable package
        # Step 8: Install the vulnerable packages
def send_alert(message):
    """Send an email alert with the given message."""
    # Setup the MIME
    msg = MIMEMultipart()
    msg['From'] = ALERT_EMAIL_ADDRESS
    msg['To'] = RECIPIENT_EMAIL
    msg['Subject'] = SUBJECT
    # Record the MIME types of both parts - text/plain and text/html.
    part1 = MIMEText(message, 'plain')
  
    # Attach parts into message container.
    # According to RFC 2046, the last part of a multipart message, in this case
    # the HTML message, is best and preferred.
    msg.attach(part1)
  
    # The HTML message
    part2 = MIMEText(message, 'html')
  
    # Attach parts into message container.
    msg.attach(part2)
  
    # The image file
    # fp = open(IMAGE_FILE, 'rb')
  
    # # Define the image's MIME type, main type is image
    # img = MIMEImage(fp.read(), _subtype=fp.content_type)
  
    # # Define the image's ID as referenced above
    # img.add_header('Content-ID', '<image1>')
  
    # # Attach image to message
  
    # msg.attach(img)
  
    # # Open a plain text file for reading.  For this example, assume that
    # # the text file contains only ASCII characters.
    # fp = open(TEXT_FILE, 'rb')
  
    # # Create a text/plain message
    # msg = MIMEText(fp.read(), 'plain')
  
    # # Define the message's MIME type
    # msg.set_type('text/plain')
  
    # # Define the message's ID
    # msg['Message-ID'] = uuid.uuid4()
  
    # # Attach the message to the MIMEMultipart object
    # msg.add_header('Content-Disposition', 'attachment', filename=TEXT_FILE)
# Add the body of the email to the MIME message
    msg.attach(MIMEText(BODY + "\n\n" + message, 'plain'))
  
    # Create SMTP session for sending the mail
    s = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
    # start TLS for security
    s.starttls()
  
    # Authentication
    s.login(SMTP_USERNAME, SMTP_PASSWORD)
  
    # Send the message via the server set up earlier.
  
    s.sendmail(msg['From'], msg['To'], msg.as_string())
  
    # Terminate the SMTP session and close the connection
    s.quit()
  
def email_alert(message):
  """Send an email alert with the given message."""
  # Setup the MIME
  msg = MIMEMultipart()
  msg['From'] = ALERT_EMAIL_ADDRESS
  msg['To'] = RECIPIENT_EMAIL
  msg['Subject'] = SUBJECT
  
  # Record the MIME types of both parts - text/plain and text/html.
  part1 = MIMEText(message, 'plain')
  
  # Attach parts into message container.
  # According to RFC 2046, the last part of a multipart message, in this case
  # the HTML message, is best and preferred.
  msg.attach(part1)
  
  # The HTML message
  part2 = MIMEText(message, 'html')
  
  # Attach parts into message container.
  msg.attach(part2)
  try:
        # set up the SMTP server
        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls()  # Enable security
        server.login(ALERT_EMAIL_ADDRESS, ALERT_EMAIL_PASSWORD)  # login with mail_id and password

        # send the email
        to = RECIPIENT_EMAIL
        server.sendmail(ALERT_EMAIL_ADDRESS, RECIPIENT_EMAIL, msg.as_string())

        # Terminate the SMTP session and close the connection
        # terminate the SMTP session
        server.quit()
        print("Alert email sent successfully to", RECIPIENT_EMAIL)
    except Exception as e:
        # Print any error messages to stdout
        print("Failed to send alert email: ", e)

# Note: Before using this function, make sure to replace placeholder values with your actual information.


# Other imports...

# Configuration for email alerts (placeholder values)
ALERT_EMAIL_ADDRESS = "your_email@example.com"
ALERT_EMAIL_PASSWORD = "your_password"
SMTP_SERVER = "smtp.example.com"
SMTP_PORT = 587
RECIPIENT_EMAIL = "recipient@example.com"
SUBJECT = "intrusion- Alert"
BODY = "there has been a system itrusion (or attack)"
TEXT_FILE = "text_file.txt"
# End of configuration

# Email alerts
email_alert("Alert: Intrusion Detected")

class  AlertHandler(FileSystemEventHandler):
    def on_modified(self, event):
        super(AlertHandler, self).on_modified(event)
        if not event.is_directory:
            logging.info(f"File {event.src_path} has been modified.")
            send_alert(f"File {event.src_path} has been modified.")

    # Similar methods for on_created and on_deleted can be added
    # if needed.

# Setup the watchdog
event_handler = AlertHandler()
watcher = Observer()
watcher.schedule(event_handler, path="/home/pi/Desktop/", recursive=True)
watcher.start()
# Start the watchdog
try:
    while True:
        time.sleep(1)
except KeyboardInterrupt:
    watcher.stop()
  
# Stop the watchdog
watcher.join()
# End of watchdog
# End of script
def send_alert(message):
    """Send an email alert with the given message."""
    try:
        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls()
        server.login(ALERT_EMAIL_ADDRESS, ALERT_EMAIL_PASSWORD)
        server.sendmail(ALERT_EMAIL_ADDRESS, RECIPIENT_EMAIL, message)
        server.quit()
        logging.info("Alert sent successfully.")
    except Exception as e:
        logging.error(f"Failed to send alert: {e}")        # The code here is assumed to be inside the 'try' block of the send_alert function.

          # send the email
          server.sendmail(ALERT_EMAIL_ADDRESS, RECIPIENT_EMAIL, msg.as_string())
      

          # Terminate the SMTP session and close the connection
          server.quit()
          print("Alert email sent successfully to", RECIPIENT_EMAIL)
      except Exception as e:
        # Print any error messages to stdout
        print("Failed to send alert email: ", e)
      
        
# Note: Before using this function, make sure to replace placeholder values with your actual information.

def start_monitoring(directory_path):
    logging.info(f"Starting to monitor {directory_path}")
    event_handler = AlertHandler()
    observer = Observer()
    observer.schedule(event_handler, directory_path, recursive=True)
    observer.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()

# Start monitoring with real-time alerts
start_monitoring(MONITOR_DIR)
# Start monitoring with email alerts
#start_monitoring(MONITOR_DIR, True)
# End of script
def send_alert(message):
    """Send an email alert with the given message."""
    try:
        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls()
        server.login(ALERT_EMAIL_ADDRESS, ALERT_EMAIL_PASSWORD)
        server.sendmail(ALERT_EMAIL_ADDRESS, RECIPIENT_EMAIL, message)
        server.quit()
        logging.info("Alert sent successfully.")
    except Exception as e:
        logging.error(f"Failed to send alert: {e}")        # The code here is assumed to be inside the 'try' block of the send_alert function.
      
          # send the email
          server.sendmail(ALERT_EMAIL_ADDRESS, RECIPIENT_EMAIL, msg.as_string())
      
          # Terminate the SMTP session and close the connection
          server.quit()
      
          print("Alert email sent successfully to", RECIPIENT_EMAIL)
      except Exception as e:
        # Print any error messages to stdout
        print("Failed to send alert email: ", e)
      
        
# Note: Before using this function, make sure to replace placeholder values with your actual information.
def start_monitoring(directory_path, send_alerts=False):
    logging.info(f"Starting to monitor {directory_path}")
    event_handler = AlertHandler()
    observer = Observer()
    observer.schedule(event_handler, directory_path, recursive=True)
    observer.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()
    if send_alerts:
        send_alert(f"Monitoring {directory_path} has stopped.")
    else:
        logging.info(f"Monitoring {directory_path} has stopped.")

# Start monitoring with real-time alerts
start_monitoring(MONITOR_DIR)
# Start monitoring with email alerts
#start_monitoring(MONITOR_DIR, True)
# End of script
def send_alert(message):
    """Send an email alert with the given message."""
    try:
        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls()
        server.login(ALERT_EMAIL_ADDRESS, ALERT_EMAIL_PASSWORD)
        server.sendmail(ALERT_EMAIL_ADDRESS, RECIPIENT_EMAIL, message)
        server.quit()
        logging.info("Alert sent successfully.")
    except Exception as e:
        logging.error(f"Failed to send alert: {e}")        # The code here is assumed to be inside the 'try' block of the send_alert function.
      
          # send the email
          server.sendmail(ALERT_EMAIL_ADDRESS, RECIPIENT_EMAIL, msg.as_string())
      
          # Terminate the SMTP session and close the connection
          server.quit()
      
          print("Alert email sent successfully to", RECIPIENT_EMAIL)
      except Exception as e:
        # Print any error messages to stdout
print("Failed to send alert email: ", e)
        
import logging
from pathlib import Path
from scapy.all import IP, TCP, sr1, RandShort
from scapy.layers.inet import IPerror
from scapy.layers.inet6 import IPv6error

# Set up logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(message)s")

# Define the path to the monitored directory
MONITOR_DIR = "/home/user/monitored_directory"
# Define the path to the log file
LOG_FILE = "/home/user/monitored_directory/log.txt"
# Define the email address to send alerts to
RECIPIENT_EMAIL = "ztejd@example.com"
# Define the SMTP server and port for sending alerts
SMTP_SERVER = "smtp.example.com"
SMTP_PORT = 587
# Define the email address and password for sending alerts
ALERT_EMAIL_ADDRESS = "ztejd@example.com"
ALERT_EMAIL_PASSWORD = "your_password"
# Define the email subject and message for sending alerts
# Define the subject and body of the email alert
ALERT_SUBJECT = "Monitored directory has been corrupted"


# Define a class for handling monitoring events
class AlertHandler(FileSystemEventHandler):
    def __init__(self):
        self.log_file = open(LOG_FILE, "a")
      
    def on_created(self, event):
        # Log the creation of a new file
        logging.info(f"{event.src_path} has been created.")
        self.log_file.write(f"{event.src_path} has been created.\n")
        self.log_file.flush()
      
    def on_deleted(self, event):
        # Log the deletion of a file
        logging.info(f"{event.src_path} has been deleted.")
        self.log_file.write(f"{event.src_path} has been deleted.\n")
      
    def on_modified(self, event):
        # Log the modification of a file
        logging.info(f"{event.src_path} has been modified.")
        self.log_file.write(f"{event.src_path} has been modified.\n")
        self.log_file.flush()
      
    def on_moved(self, event):
        # Log the movement of a file
        logging.info(f"{event.src_path} has been moved.")
        self.log_file.write(f"{event.src_path} has been moved.\n")
        self.log_file.flush()
      
    def on_moved_from(self, event):
        # Log the movement of a file from a parent directory
        logging.info(f"{event.src_path} has been moved from {event.src_path.parent}.")
        self.log_file.write(f"{event.src_path} has been moved from {event.src_path.parent}.\n")
      
    def on_moved_to(self, event):
        # Log the movement of a file to a parent directory
        logging.info(f"{event.src_path} has been moved to {event.dest_path.parent}.")
        self.log_file.write(f"{event.src_path} has been moved to {event.dest_path.parent}.\n")
      
    def on_modified_final(self, event):
        # Log the modification of a file after it has been moved
        logging.info(f"{event.src_path} has been modified after it has been moved.")
      
    def on_moved_final(self, event):
        # Log the movement of a file after it has been moved
        logging.info(f"{event.src_path} has been moved after it has been moved.")
      
    def on_moved_from_final(self, event):
        # Log the movement of a file from a parent directory after it has been moved
        logging.info(f"{event.src_path} has been moved from {event.src_path.parent} after it has been moved.")
      
    def on_moved_to_final(self, event):
        # Log the movement of a file to a parent directory after it has been moved
        logging.info(f"{event.src_path} has been moved to {event.dest_path.parent} after it has been moved.")
      
    def on_deleted_final(self, event):
        # Log the deletion of a file after it has been moved
        logging.info(f"{event.src_path} has been deleted after it has been moved.")
      
    def on_moved_error(self, event):
        # Log the movement of a file that failed
        logging.info(f"{event.src_path} has been moved but failed to move.")
      
    def on_moved_error_final(self, event):
        # Log the movement of a file that failed after it has been moved

      
# End of the program

MONITOR_DIR = '/home/runner/Threat-Hunter/monitor_dir'

def monitor_dir():
    """Monitors the specified directory for changes."""
    path = Path(MONITOR_DIR)
    if not path.exists():
        path.mkdir(parents=True)
    # Further functionality could include setting up a watchdog observer here
    logging.info(f"Monitoring directory: {MONITOR_DIR}")

    # Set up basic configuration for logging
    logging.basicConfig(level=logging.INFO)

    # Set up a logger for the monitored directory
    logger = logging.getLogger(MONITOR_DIR)
  
    # Set up a handler for logging messages to the log file
    handler = logging.FileHandler(LOG_FILE)
  
    # Set up a formatter for the log messages
    formatter = logging.Formatter("%(asctime)s - %(message)s")
  
    # Add the formatter to the handler
    handler.setFormatter(formatter)
  
    # Add the handler to the logger
    logger.addHandler(handler)
  
    # Start monitoring the directory
    while True:
        # Scan the directory for new files
        for file in path.iterdir():
            # Check if the file is a text file
            if file.is_file() and file.suffix == ".txt":
                # Open the file for reading
                with open(file, "r") as f:
                    # Read the contents of the file
                    contents = f.read()
                  
                # Check if the contents of the file have changed
                if contents != "":
                    # Send an alert email
                    send_alert(contents)
                  
                    # Log the change to the log file
                    logger.info(f"{file.name} has changed")
                  
        # Sleep for 1 second
        time.sleep(1)
      
# Start monitoring with real-time alerts
monitor_dir()
class IntrusionPreventionSystem:
  def cd pyclamd.ClamdUnixSocket()
      # Check if daemon is reachable
      try:
          cd.ping()
      except pyclamd.ConnectionError:
          # Start the daemon if not running (method of starting might differ)
          print('Starting ClamAV daemon')
          # This would be where you start the daemon, e.g., by calling a system command

      # Update the virus database
      cd.reload()
    

  def scan_file(cd, file):
      # Scan a specific file
      result = cd.scan_file(file)
      if result is None:
          print(f"{file} is clean!")
      else:
          print(f"Malware detected in {file}: {result}")

  # Example usage 
      try:
          for ip in range(1, 255):
              ip_address = f'192.168.0.{ip}'
              res = subprocess.Popen(['', '-c', '1', ip_address], stdout=subprocess.PIPE).communicate()[0]
              if '1 packets transmitted, 1 packets received' in str(res):
                  print(f'IP Address: {ip_address} is online.')
      except Exception as e:
          print(f'An error occurred: {e}')

  # Search for suspicious patterns in logs

      def search_logs(path_to_logs):
       pattern = r'((?:[0-9]{1,3}\.){3}[0-9]{1,3}).*?(?i)(password|login|user|attack|failed|error)'
        # Search for suspicious patterns in logs
  for file in path_to_logs.iterdir():
          if file.is_file():
              with open(file, 'r') as f:
                  content = f.read()
                  matches = re.(pattern, content)
                  if matches:
                      print(f'Suspicious pattern found in {file}: {matches}')
                  else:
                      print(f'No suspicious patterns found in {file}')
if os.path.isfile(os.path.join(path_to_logs, file_name)):
                  with open(os.path.join(path_to_logs, file_name), 'r') as file:
                      for line in file:
                          if re.search(pattern, line):
                            print(f'Suspicious pattern found in {file_name}: {line}')
                            break
                      else:
                          print(f'No suspicious patterns found in {file_name}')
                        
# Search for suspicious patterns in logs
def search_logs(path_to_logs
  def detect_anomalies(host='127.0.0.1', port_range=(1, 1024)):
      open_ports = []
      for port in range(*port_range):
          sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
          sock.settimeout(1)
          result = sock.connect_ex((host, port))
          if result == 0:
              open_ports.append(port)
          sock.close()

      if len(open_ports) > 5:  # This threshold can be adjusted based on what's considered "unusual"
          print(f'Potential network anomaly detected. Number of open ports: {len(open_ports)}. Ports: {open_ports}')

  # Run bot functions
  def run_threat_hunting_bot():
      scan_network()
      search_logs('/var/log/')
      detect_anomalies()

  if __name__ == '__main__':
      run_threat_hunting_bot()

  # Define a basic network scanner
  def scannetwork():
    try:
      for ip in range(1, 255):
        ip_address = f'192.168.0.{ip}'
        res = subprocess.Popen(['', '-c', '1', ip_address], stdout=subprocess.PIPE).communicate()[0]
        if '1 packets transmitted, 1 packets received' in str(res):
          print(f'IP Address: {ip_address} is online.')
          # Perform other network-related tasks here
    except Exception as e:
      print(f'An error occurred: {e}')

  # Search for suspicious patterns in logs
  def search_logs(path_to_logs):
    pattern = r'((?:[0-9]{1,3}\.){3}[0-9]{1,3}).*?(?i)(password|login|user|attack|failed|error)'
    try:
      for file_name in os.listdir(path_to_logs):
        if os.path.isfile(os.path.join(path_to_logs, file_name)):
          with open(os.path.join(path_to_logs, file_name), 'r') as file:
            for line in file:
              if re.search(pattern, line):
                print(f'Suspicious activity detected in {file_name}: {re.search(pattern, line).group()}')
                # Perform other log-related tasks here
    except Exception as e:
      print(f'An error occurred during log search: {e}')


  # Detect network anomalies like unusual number of open ports
  def detect_anomalies(host='127.0.0.1', port_range=(1, 1024)):
    open_ports = []
    for port in range(*port_range):
      sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
      sock.settimeout(1)
      result = sock.connect_ex((host, port))
      if result == 0:
        open_ports.append(port)
        sock.close()
    if len(open_ports) > 5:  # This threshold can be adjusted based on what's considered "unusual"
      print(f'Potential network anomaly detected. Number of open ports: {len(open_ports)}. Ports: {open_ports}')


 # Run bot functions
  def run_threat_hunting_bot():
    scan_network()
    search_logs('/var/log/')
    detect_anomalies()

  if __name__ == '__main__':
    run_threat_hunting_bot()

  # Define a basic network scanner
  def scan_network():
    try:
      for ip in range(1, 255):
        ip_address = f'192.168.0.{ip}'
        res = subprocess.Popen(['', '-c', '1', ip_address], stdout=subprocess.PIPE).communicate()
    def __init__(self, host_ip, host_port):
        self.host_ip = host_ip
        self.host_port = host_port

    def is_port_open(self):
        """Checks if specified port on the host is open."""
        src_port = RandShort()
        response = sr1(
            IP(dst=self.host_ip)/TCP(sport=src_port, dport=self.host_port, flags="S"), 
            timeout=10, 
            verbose=False
        )
        return True if response and response.getlayer(TCP).flags == 0x12 else False
      

monitor_dir()  # Call the function to start monitoring the directory
MONITOR_DIR = '/home/runner/Threat-Hunter/monitor_dir'
LOG_DIR = '/home/runner/Threat-Hunter/log_dir'
LOG_FILE = '/home/runner/Threat-Hunter/log_file'
LOG_FORMAT = '%(asctime)s - %(name)s - %(levelname)s
LOG_LEVEL = logging.DEBUG
LOG_FILE_SIZE = 5 * 1024 * 1024  # 5 MB
LOG_FILE_COUNT = 5  # Keep 5 log files
LOG_FILE_NAME = 'threat_hunting_bot.log'
LOG_FILE_PATH = os.path.join(LOG_DIR, LOG_FILE_NAME)
LOG_FILE_HANDLER = logging.handlers.RotatingFileHandler(
  LOG_FILE_PATH, maxBytes=LOG_FILE_SIZE, backupCount=LOG_FILE_COUNT
)
LOG_FILE_HANDLER.setFormatter(logging.Formatter(LOG_FORMAT))
LOG_FILE_HANDLER.setLevel(LOG_LEVEL)
LOG_FILE_HANDLER.setFormatter(logging.Formatter(LOG_FORMAT)

                              
                              
    def monitor_dir():
    # Monitor the monitor_dir for new files
    # Monitor the monitor_dir for newfiles
# This will create the MONITOR_DIR if it does not exist
if not os.path.exists(MONITOR_DIR):
    os.makedirs(MONITOR_DIR)
  
# This will create the LOG_DIR if it does not exist
if not os.path.exists(LOG_DIR):
    os.makedirs(LOG_DIR)
  
# This will create the LOG_FILE if it does not exist
if not os.path.exists(LOG_FILE):
    open(LOG_FILE, 'a').close()
  
# This will add the LOG_FILE_HANDLER to the LOG_FILE
logging.basicConfig(filename=LOG_FILE, level=LOG_LEVEL, 
                    format=LOG_FORMAT, filemode='a',
                    handlers=[logging.FileHandler(LOG_FILE), 
                              logging.StreamHandler()])

import subprocess
import sys
import time
import logging
import os
import shutil
import glob
import json
import psutil
import netifaces
import subprocess
import shlex
import boto3
import botocore
#Specify the AWS region, for example 'us-west-2'
l = boto3.client('lambda', region_name='us-west-2')
#Specify the function name, for example 'my-function'
l.invoke(FunctionName='my-function', InvocationType='Event')
#Specify the function name, for example 'my-function'


def lambda_handler(event, context):
  print(event)
  print(context)
  print(event['body'])
  print(event['headers'])

  print(event['queryStringParameters'])
  print(event['pathParameters'])
  print(event['stageVariables'])
  print(event['requestContext'])
  print(event['path'])
  print(event['httpMethod'])
  print(event['multiValueHeaders'])
  print(event['multiValueQueryStringParameters'])
  print(event['stage'])
  print(event['body'])
  print(event['isBase64Encoded'])
  print(event['queryStringParameters'])
  print(event['pathParameters'])
  print(event['stageVariables'])
  print(event['requestContext'])
  print(event['path'])
  print(event['httpMethod'])
  print(event['multiValueHeaders'])
  print(event['multiValueQueryStringParameters'])
  print(event['stage'])
  print(event['body'])
  print(event['isBase64Encoded'])
  print(event['queryStringParameters'])
  print(event['pathParameters'])
  print(event['stageVariables'])
  print(event['requestContext'])
  print(event['path'])
  print(event['httpMethod'])
  print(event['multiValueHeaders'])
  print(event['multiValueQueryString'
              'Parameters'])
import os
import hashlib
from time import sleep
# Path to the directory you want to monitor
MONITOR_DIR = "/path/to/your/important/directory"

# Time interval for the checks (in seconds)
CHECK_INTERVAL = 10

# State file to store the previous state of the directory
STATE_FILE = "monitor_state.json"

# Email settings for sending alert (example uses Gmail)
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587
EMAIL_ADDRESS = "your_email@gmail.com"
EMAIL_PASSWORD = "your_password"
import os
import os

MONITOR_DIR = '/home/runner/Threat-Hunter/monitor_dir'

try:
    # This will create the MONITOR_DIR if it does not exist
    if not os.path.exists(MONITOR_DIR):
        os.makedirs(MONITOR_DIR)
except OSError as e:
    if e.errno == errno.EROFS:  # Read-only file system
        print(f"Unable to create directory {MONITOR_DIR}: Read-only file system")
    else:
        print(f"Unable to create directory {MONITOR_DIR}: {e.strerror}")

if not os.path.exists(MONITOR_DIR):
    os.makedirs(MONITOR_DIR)
    print("Directory created")
def initialize_state():
    state = {}

    for filename in os.listdir(MONITOR_DIR):
        path = os.path.join(MONITOR_DIR, filename)
        state[path] = get_file_hash(path)
    return state

def get_file_hash(path):
    hasher = hashlib.sha256()
    with open(path, 'rb') as f:
        hasher.update(f.read())
    return hasher.hexdigest()

def detect_changes(old_state, new_state):
    changes = []
    for path, old_hash in old_state.items():
        if path not in new_state:
            changes.append(f"File deleted: {path}")
        elif old_hash != new_state[path]:
            changes.append(f"File changed: {path}")
    for path in new_state:
        if path not in old_state:
            changes.append(f"File added: {path}")
    return changes

def send_email_alert(subject, message):
    import smtplib
    from email.mime.text import MIMEText

    msg = MIMEText(message)
    msg['Subject'] = subject
    msg['From'] = EMAIL_ADDRESS
    msg['To'] = EMAIL_ADDRESS

    server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
    server.starttls()
    server.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
    server.sendmail(EMAIL_ADDRESS, [EMAIL_ADDRESS], msg.as_string())
    server.quit()

def load_state():
    if os.path.exists(STATE_FILE):
        with open(STATE_FILE) as f:
            return json.load(f)

    return initialize_state()

def save_state(state):
    with open(STATE_FILE, 'w') as f:
        json.dump(state, f)

def main():
    old_state = load_state()
    while True:
        new_state = initialize_state()
        changes = detect_changes(old_state, new_state)
        if changes:
            send_email_alert("Intrusion detected!", "\n".join(changes))
        old_state = new_state
        save_state(new_state)
        sleep(CHECK_INTERVAL)

if __name__ == "__main__":
    main()
def respond_tointrusion(changes):
    # Example response actions to an intrusion
    print("Intrusion detected! Taking action...")

    # Isolate affected systems
    isolated_systems = isolate_systems(changes)

    # Notify appropriate personnel or systems
    notify_security_team(changes)

    # Disable network access if necessary
    disable_network_access(isolated_systems)

    # Log the intrusion for further investigation
    log_intrusion(changes)

def isolatesystems(changes):
    # Example function to isolate affected systems
    isolated_systems = []
    for change in changes:
        filepath = change.split(": ")[1]
        system = os.path.dirname(filepath)
        if system not in isolated_systems:
            # In a real scenario you might disable network interfaces or perform other isolation steps
            print(f"Isolating system: {system}")
            isolated_systems.append(system)
    return isolated_systems

def notify_security_team(changes):
    # Example function to notify the security team of the intrusion
    alert_message = "Intrusion detected! The following changes were observed:\n" + "\n".join(changes)
    # In a real scenario, you might send an email or alert through monitoring systems
    print("Notifying security team: ")
    print(alert_message)

def disable_network_access(systems):
    # Example function to disable network access for the provided list of systems
    for system in systems:
        # In a real scenario, you might interact with network switches, firewalls, or use system commands
        print(f"Disabling network access for {system}")

def log_intrusion(changes):
    # Example function to log an intrusion
    with open("intrusion_log.txt", "a") as log_file:
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime())
        log_entry = f"{timestamp} - Intrusion detected:\n{''.join(changes)}\n"
        log_file.write(log_entry)

# You would call this function from within the main detection loop when changes have been detected
if __name__ == "__main__":
    # Example scenario where changes have been detected
    detected_changes = [
        "File changed: /path/to/your/important/directory/sensitive_file.txt",
        "File deleted: /path/to/your/important/directory/old_file.txt"
    ]

    respond_tointrusion(detected_changes)

def respond_tointrusion(changes):
    # Example response actions to an intrusion
    print("Intrusion detected! Taking action...")
  
    # Isolate affected systems
    isolated_systems = isolate_systems(changes)
  
    # Notify appropriate personnel or systems
    notify_security_team(changes)
  
    # Disable network access if necessary
    disable_network_access(isolated_systems)
  
    # Log the intrusion for further investigation
    log_intrusion(changes)
  
def isolatesystems(changes):
    # Example function to isolate affected systems
    isolated_systems = []
    for change in changes:
        filepath = change.split(": ")[1]
        system = os.path.dirname(filepath)
        if system not in isolated_systems:
            # In a real scenario you might disable network interfaces or perform other isolation steps
            print(f"Isolating system: {system}")
            isolated_systems.append(system)
    return isolated_systems
  
def notify_security_team(changes):
    # Example function to notify the security team of the intrusion
    alert_message = "Intrusion detected! The following changes were observed:\n" + "\n".join(changes)
    # In a real scenario, you might send an email or alert through monitoring systems
    print("Notifying security team: ")
    print(alert_message)
  
def disable_networkaccess(systems):
    # Example function to disable network access for the provided list of systems
    for system in systems:
        # In a real scenario, you might interact with network switches, firewalls, or use system commands
        print(f"Disabling network access for {system}")
      
def logintrusion(changes):
    # Example function to log an intrusion
    with open("intrusion_log.txt", "a") as log_file:
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime())
        log_entry = f"{timestamp} - Intrusion detected:\n{''.join(changes)}\n"
        log_file.write(log_entry)
      
# You would call this function from within the main detection loop when changes have been detected
if __name__ == "__main__":
    # Example scenario where changes have been detected
    detected_changes = [
        "File changed: /path/to/your/important/directory/sensitive_file.txt",
        "File deleted: /path/to/your/important/directory/old_file.txt"
    ]
  respond_to_intrusion(detected_changes)
  def respond_tointrusion(changes):
    # Example response actions to an intrusion
    print("Intrusion detected! Taking action...")
  
    # Isolate affected systems
    isolated_systems = isolate_systems(changes)
  
    # Notify appropriate personnel or systems
    notify_security_team(changes)
  
    # Disable network access if necessary
    disable_network_access(isolated_systems)
  
    # Log the intrusion for further investigation
    log_intrusion(changes)
  
def isolate_systems(changes):
    # Example function to isolate affected systems
    isolated_systems = []
    for change in changes:
        filepath = change.split(": ")[1]
        system = os.path.dirname(filepath)
        if system not in isolated_systems:
            # In a real scenario you might disable network interfaces or perform other isolation steps
            print(f"Isolating system: {system}")
            isolated_systems.append(system)
    return
def respond_to_intrusion(changes):

    print("Intrusion detected! Taking action...")
  
    # Isolate affected systems
    isolated_systems = isolate_systems(changes)
  
    # Notify appropriate personnel or systems
    notify_security_team(changes)
  
    # Disable network access if necessary
    disable_network_access(isolated_systems)
    isolated_systems = isolate_affected_systems(changes)

    # Notify appropriate personnel or systems
    notify_security_team(changes)

    # Disable network access if necessary
    disable_network_access(isolated_systems)

    # Log the intrusion for further investigation
    log_intrusion(changes)
  def isolate_affected_systems(changes):
    isolated_systems = []
    for change in changes:
        filepath = change.split(": ")[1]
        system = os.path.dirname(filepath)
        if system not in isolated_systems:
            # In a real scenario you might disable network interfaces or perform other isolation steps
            print(f"Isolating system: {system}")
            isolated_systems.append(system)
          
    return isolated_systems
  
def notify_security_team(changes):
    # Example function to notify the security team of the intrusion
  
    alert_message = "Intrusion detected! The following changes were observed:\n" + "\n".join(changes)
  
    # In a real scenario, you might send an email or alert through monitoring systems
    print("Notifying security team: ")
  
    print(alert_message)
  
def disable_network_access(systems):
  # Example function to disable network access for the provided list of systems
  for system in systems:
      print(f"Disabling network access for {system}")
    
def log_intrusion(changes):
  # Example function to log an intrusion
  with open("intrusion_log.txt", "a") as log_file:
      timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime())
      log_entry = f"{timestamp} - Intrusion detected:\n{''.join(changes)}\n"
      log_file.write(log_entry)
    
# You would call this function from within the main detection loop when changes have been detected
if __name__ == "__main__":
  # Example scenario where changes have been detected
  detected_changes = [
      "File changed: /path/to/your/important/directory/sensitive_file.txt",
      "File deleted: /path/to/your/important/directory/old_file.txt"
  ]
  respond_to_intrusion(detected_changes)
  def respond_tointrusion(changes):
    # Example response actions to an intrusion
    print("Intrusion detected! Taking action...")
    # Isolate affected systems
    isolated_systems = isolate_systems(changes)
    # Notify appropriate personnel or systems
    notify_security_team(changes)
    # Disable network access if necessary
    disable_network_access(isolated_systems)
    # Log the intrusion for further investigation
    log_intrusion(changes)
    # You would call this function from within the main detection loop when changes have been detected
  def isolate_affected_systems(changes):
    # Example function to isolate affected systems
    isolated_systems = []
    for change in changes:
        filepath = change.split(": ")[1].strip()
        system = os.path.dirname(filepath)
        if system not in isolated_systems:
            # In a real scenario you might disable network interfaces or perform other isolation steps
            print(f"Isolating system: {system}")
            isolated_systems.append(system)
    return isolated_systems

def notify_security_team(changes):
    # Example function to notify the security team of the intrusion
    alert_message = "Intrusion detected! The following changes were observed:\n" + "\n".join(changes)
    # In a real scenario, you might send an email or alert through monitoring systems
    print("Notifying security team:")
    print(alert_message)

def disable_network_access(isolated_systems):
    # Example function to disable network access for the provided list of systems
    for system in isolated_systems:
        # In a real scenario, you might interact with network switches, firewalls, or use system commands
        print(f"Disabling network access for {system}")

def log_intrusion(changes):
    # Example function to log an intrusion
    with open("intrusion_log.txt", "a") as log_file:
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime())
        log_entry = f"{timestamp} - Intrusion detected:\n{'n'.join(changes)}\n\n"
        log_file.write(log_entry)

# You would call this function from within the main detection loop when changes have been detected
if __name__ == "__main__":
    # Example scenario where changes have been detected
    detected_changes = [
        "File changed: /path/to/your/important/directory/sensitive_file.txt",
        "File deleted: /path/to/your/important/directory/old_file.txt"
    ]

    respond_to_intrusion(detected_changes)
  
def respond_tointrusion(changes):
    # Example response actions to an intrusion
    print("Intrusion detected! Taking action...")

import os
import subprocess
def restore_backup(backup_path, target_path):
    """Restore backup files to a specific target directory."""
    if not os.path.exists(backup_path):
        print("Backup path does not exist.")
        return False

    try:
        subprocess.run(['cp', '-a', backup_path + '/.', target_path], check=True)
        print(f"Successfully restored backup from {backup_path} to {target_path}")
        return True
    except subprocess.CalledProcessError as e:
        print(f"Failed to restore backup: {e}")
        return False

def recover_from_logs(log_file_path, commands_to_reverse):
    """Use log file to reverse malicious actions."""
    if not os.path.exists(log_file_path):
        print("Log file does not exist.")
        return False

    try:
        with open(log_file_path, "r") as log_file:
            logs = log_file.readlines()

        for cmd in reversed(logs):
            if cmd.strip() in commands_to_reverse:
                # Implement the logic to reverse the specific command
                print(f"Reverse command: {cmd.strip()}")
                # Example: reversing a deletion
                if cmd.strip().startswith("rm "):
                    file_to_recover = cmd.strip().split(" ")[1]
                    # Logic to recover the deleted file
                    # In a real-world scenario, implement the file recovery (e.g., from a backup)

        print("Successfully recovered from logs.")
        return True
    except Exception as e:
        print(f"Failed to recover from logs: {e}")
        return False

# Example usage (paths and variables would need to be adjusted to the specific use case)
backup_path = '/path/to/backup'
target_path = '/path/to/recover'

# Restore from backup
restore_backup(backup_path, target_path)

# Recover from logs
log_file_path = '/path/to/logs'
commands_to_reverse = ['rm', 'mv']  # Specify which commands to look for and reverse
recover_from_logs(log_file_path, commands_to_reverse)
      
def restore_backup(backup_path, target_path):
  """Restore backup files to a specific location."""
  # ... rest of the restore_backup function code ...

def recover_from_logs(log_file_path, commands_to_reverse):
  # ... recover_from_logs function code ...
  pass

import traceback
from subprocess import Popen, PIPE
from subprocess import PIPE, STDOUT
from subprocess import check_output
from subprocess import CalledProcessError
from subprocess import TimeoutExpired
import subprocess
import uuid
from collections import OrderedDict
from pathlib import Path

def print_exception(e):
  print(e)
def print_exception_and_exit(e):
  print_exception(e)
  exit(1)
def print_exception_and_exit_with_code(e, code):
  print_exception(e)
  exit(code)
def print_exception_and_exit_with_code_and_message(e, code, message):
  print_exception(e)
  exit(code)
  print(message)
def print_exception_and_exit_with_code_and_message_and_traceback(e, code, message, traceback_str):
  print_exception(e)
  exit(code)
  print(message)
  print(traceback_str)


def print_exception_and_exit_with_code_and_message_and_traceback(
    e, code, message, tb):
  print
import socket
import sys
import traceback
from scapy.all import IP, TCP, sr1, RandShort
from scapy.all import sr1, sr1
from scapy.all import sr1

class IntrusionPreventionSystem:

    def __init__(self, host_ip, host_port):
        self.host_ip = host_ip
        self.host_port = host_port

    def is_port_open(self):
        src_port = RandShort()
        response = sr1(
            IP(dst=self.host_ip)/TCP(sport=src_port, dport=self.host_port, flags="S"), 
            timeout=10, 
            verbose=False
        )
        return True if response and response.getlayer(TCP).flags == 0x12 else False

    def ping_host(self):
        src_port = RandShort()
        response = sr1(
            IP(dst=self.host_ip)/TCP(sport=src_port, dport=self.host_port, flags="S"), 
            timeout=10, 
            verbose=False
        )
        return True if response and response.getlayer(TCP).flags == 0x12 else False

    def ping_host_with_timeout(self, timeout):
        src_port = RandShort()
        response = sr1(
            IP(dst=self.host_ip)/TCP(sport=src_port, dport=self.host_port, flags="S"),
          timeout=timeout, 
          verbose=False
        )

        return True if response and response.getlayer(TCP).flags == 0x12 else False

    def ping_host_with_timeout_and_message(self, timeout, message):
        src_port = RandShort()
        response = sr1(
            IP(dst=self.host_ip)/TCP(sport=src_port, dport=self.host_port, flags="S"),
          timeout=timeout, 
          verbose=False
        )

        return True if response and response.getlayer(TCP).flags == 0x12 else False

    def ping_host_with_timeout_and_message_and_traceback(self, timeout, message, traceback_str


    def block_ip(self, attacker_ip):
        # This is highly platform and configuration specific and may not work out of the box
        # A typical command to block an IP using iptables would look like this:
        block_command = f"iptables -A INPUT -s {attacker_ip} -j DROP"

        # Execute the command and return the output
        return subprocess.check_output(block_command, shell=True)

    def block_ip_with_timeout(self, attacker_ip, timeout):
        # This is highly platform and configuration specific and may not work out of the box

        # A typical command to block an IP using iptables would look like this:





        # Execute the command and return the output
        return subprocess.check_output(block_command, shell=True)

    def block_ip_with_timeout_and_message(self, attacker_ip, timeout, message):
        # This is highly platform and configuration specific and may not work out of the box

        # A typical command to block an IP using iptables would look like this:
      
        # Execute the command and return the output
        return subprocess.check_output(block_command, shell=True)
      
    def block_ip_with_timeout_and_message_and_traceback(self, attacker_ip, timeout, message, traceback_str):
        # This is highly platform and configuration specific and may not work out of the box
      
        # A typical command to block an IP using iptables would look like this:
      
        # Execute the command and return the output
        return subprocess.check_output(block_command, shell=True)
      
    def unblock_ip(self, attacker_ip):
        # This is highly platform and configuration specific and may not work out of the box
        # A typical command to unblock an IP using iptables would look like this:
        unblock_command = f"iptables -D INPUT -s {attacker_ip}
        # Execute the command and return the output
        return subprocess.check_output(unblock_command, shell=True)
     
     def unblock_ip_with_timeout(self, attacker_ip, timeout):
        # This is highly platform and configuration specific and may not work out of the box
        # A typical command to unblock an IP using iptables would look like this:
        unblock_command = f"iptables -D INPUT -s {attacker_ip}
          # Execute the command and return the output
        return subprocess.check_output(unblock_command, shell=True)
      
    def unblock_ip_with_timeout_and_message(self, attacker_ip, timeout, message):
        # This is highly platform and configuration specific and may not work out of the box
        # A typical command to unblock an IP using iptables would look like this:
        unblock_command = f"iptables -D INPUT -s {attacker_ip}
        # Execute the command and return the output
        return subprocess.check_output(unblock_command, shell=True)
        
    def unblock_ip_with_timeout_and_message_and_traceback(self, attacker_ip, timeout, message, traceback_str):
        # This is highly platform and configuration specific and may not work out of the box
        # A typical command to unblock an IP using iptables would look like this:
        unblock_command = f"iptables -D INPUT -s {attacker_ip)
                                                  # Execute the command and return the output
                                                  return subprocess.check_output(unblock_command, shell=True)
      
    def ping_host_with_timeout_and_message_and_traceback(self, timeout, message, traceback_str):
        # This is highly platform and configuration specific and may not work out of the box
        # A typical command to ping a host using ping would look like this:
        ping_command = f"ping -c 1 {host}"
        # Execute the command and return the output
        return subprocess.check_output(ping_command, shell=True)
      
    def ping_host_with_timeout_and_message(self, timeout, message):
        # This is highly platform and configuration specific and may not work out of the box
        # A typical command to ping a host using ping would look like this:
        ping_command = f"ping -c 1 {host}"
        # Execute the command and return the output
        return subprocess.check_output(ping_command, shell=True)
      
    def ping_host_with_timeout(self, timeout):
        # This is highly platform and configuration specific and may not work out of the box
        # A typical command to ping a host using ping would look like this:
        ping_command = f"ping -c 1 {host}"
        # Execute the command and return the output
        return subprocess.check_output(ping_command, shell=True)
      
    def ping_host(self, host):
        # This is highly platform and configuration specific and may not work out of the box
        # A typical command to ping a host using ping would look like this:
        ping_command = f"ping -c 1 {host}"
        # Execute the command and return the output
        return subprocess.check_output(ping_command, shell=True)
      
    def ping_host_with_timeout_and_message_and_traceback(self, timeout, message, traceback_str):
        # This is highly platform and configuration specific and may not work out of the box
        # A typical command to ping a host using ping would look like this:
        ping_command = f"ping -c 1 {host}"
        # Execute the command and return the output
        return subprocess.check_output(ping_command, shell=True)
      
    def ping_host_with_timeout_and_message(self, timeout, message):
        # This is highly platform and configuration specific and may not work out of the box
        # A typical command to ping a host using ping would look like this:
        ping_command = f"ping -c 1 {host}"
        # Execute the command and return the output
        return subprocess.check_output(ping_command, shell=True)
      
    def ping_host_with_timeout(self, timeout):
        # This is highly platform and configuration specific and may not work out of the box
        # A typical command to ping a host using ping would look like this:
        ping_command = f"ping -c 1 {host}"
        # Execute the command and return the output
        return subprocess.check_output(ping_command, shell=True)
      
    def ping_host_with_message_and_traceback(self, message, traceback_str):
        # This is highly platform and configuration specific and may not work out of the box
        # A typical command to ping a host using ping would look like this:
        ping_command = f"ping -c 1 {host}"
        # Execute the command and return the output
        return subprocess.check_output(ping_command, shell=True)
      
    def ping_host_with_message(self, message):
        # This is highly platform and configuration specific and may not work out of the box
        # A typical command to ping a host using ping would look like this:
        ping_command = f"ping -c 1 {host}"
        # Execute the command and return the output
        return subprocess.check_output(ping_command, shell=True)
      
    def ping_host(self, host):
        # This is highly platform and configuration specific and may not work out of the box
        # A typical command to ping a host using ping would look like this:
        ping_command = f"ping -c 1 {host}"
        # Execute the command and return the output
        return subprocess.check_output(ping_command, shell=True)
      
    def ping_host_with_timeout_and_message_and_traceback(self, timeout, message, traceback_str):
        # This is highly platform and configuration specific and may not work out of the box
        # A typical command to ping a host using ping would look like this:
        ping_command = f"ping -c 1 {host}"
        # Execute the command and return the output
        return subprocess.check_output(ping_command, shell=True)
      
    def ping_host_with_timeout_and_message(self, timeout, message):
        # This is highly platform and configuration specific and may not work out of the box
        # A typical command to ping a host using ping would look like this:
        ping_command = f"ping -c 1 {host}"
        # Execute the command and return the output
        return subprocess.check_output(ping_command, shell=True)
      
    def ping_host_with_timeout(self, timeout):
        # This is highly platform and configuration specific and may not work out of the box
        # A typical command to ping a host using ping would look like this:
        ping_command = f"ping -c 1 {host}"
        # Execute the command and return the output
        return subprocess.check_output(ping_command, shell=True)
      
    def ping_host_with_message_and_traceback(self, message, traceback_str):
        # This is highly platform and configuration specific and may not work out of the box
        # A typical command to ping a host using ping would look like this:
        ping_command = f"ping -c 1 {host}"
        # Execute the command and return the output
        return subprocess.check_output(ping_command, shell=True)
      
  
class TestPing(unittest.TestCase):
    def test_ping_host_with_timeout_and_message_and_traceback(self):
        # This is highly platform and configuration specific and may not work out of the box
        # A typical command to ping a host using ping would look like this:
        ping_command = f"ping -c 1 {host}"
        # Execute the command and return the output
        output = subprocess.check_output(ping_command, shell=True)

  
if __name__ == '__main__':
    unittest.main()

# ping_host_with_message_and_traceback()
# ping_host_with_message()
# ping_host()
# ping_host_with_timeout_and_message_and_traceback()
# ping_host_with_timeout_and_message()
# ping_host_with_timeout()
# ping_host_with_message_and_traceback()
# ping_host_with_timeout_and_message_and_traceback()
# ping_host_with_timeout_and_message()
# ping_host_with_message_and_traceback()
# ping_host_with_timeout_and_message_and_traceback()
# ping_host_with_timeout_and_message()
# ping_host_with_message_and_traceback()
# ping_host_with_timeout_and_message_and_traceback()
# ping_host_with_timeout_and_message()
# ping_host_with_message_and_traceback()
# ping_host_with_timeout_and_message_and_traceback()
# ping_host_with_timeout_and_message()
# ping_host_with_message_and_traceback()
# ping_host_with_timeout_and_message_and_traceback()
# ping_host_with_timeout_and_message()

# Define the main function
def main():
    # Create an instance of the AlertHandler class
    handler = AlertHandler()
    # Create an instance of the Observer class
    observer = Observer()
    # Start watching the DIRECTORY for changes
    observer.schedule(handler, DIRECTORY, recursive=True)
    observer.start()
    # Wait forever
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()

# Call the main function
if __name__ == "__main__":
  main()

# End of the program
print("Program Ended")
logging.info("Program Ended")
log_file.close()
sys.exit()
# End of the program


                     


