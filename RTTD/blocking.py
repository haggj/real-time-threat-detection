import sys
import time
import logging
from threading import Thread

from watchdog.observers import Observer
from watchdog.events import LoggingEventHandler, FileSystemEventHandler
import pyufw as ufw
import json
from datetime import datetime, timedelta

from RTTD.ip_analyzer import IpAnalyzer

'''
    Script that runs based on updates of the cowrie logs. 
    Blocks IP addresses, idea is to make it as much in real-time as possible.
'''

WHITELISTED_IPS = ['130.208.240.12', '85.220.40.135']

class MyEventHandler(FileSystemEventHandler):
    '''
        Handles events using Watchdog. 
    '''

    def __init__(self, path):
        self.last_ip = ""
        self.path = path

    def on_modified(self, event):
        '''
            Whenever the cowrie.json file changes, we want to add the latest IP to the firewall.
        '''
        #print(event.src_path, "modified.")
        start = time.time()
    
        ip = load_last_event(self.path) # grabs the ip
        print("IP", ip)
        # check if ip already was blocked just now 
        if ip != self.last_ip and ip != None and str(ip) not in WHITELISTED_IPS:
            rules = add_rules(ip) # blocks the ip from ufw
        if ip != None and ip not in WHITELISTED_IPS:
            self.last_ip = ip

        end = time.time()
        print("Time elapsed:", end - start, "\n")


def log_event(ip, event, rule, ip_details):
    """
        Logs an event. 
    """
    data = {
        "timestamp": datetime.now(),
        "src_ip": ip,
        "event": event,
        "rule": rule,
        "ip_details": ip_details
    }
    with open('log/rttd_logs.txt', 'a') as f:
        f.write(json.dumps(data))
    f.close()

def load_last_event(path):
    '''
        Loads the IP from the last event. 
    '''
    data=[]
    with open(path) as file:
        for line in file: pass
        if len(line) > 2:
            # If the first and second to last is not char is not '{' and '}' respectively, the line is not fully written yet.
            if line[0] == "{" and line[-2] == "}": 
                data = json.loads(line)['src_ip']
                return data
    return None

def add_rules(ip):
    """
    Adds firewall rules based on an input IP and logs this event.
    Additionally, this function calls the IpAnalyzer in order to gather detailed information.
    This is run in a new thread to not influence the performance of RTTD.
    """
    def task(ip):
        rules = [f"deny from {ip} to any port 80", f"deny from {ip} to any port 443" ]
        ip_details = IpAnalyzer().run(ip)
        for rule in rules:
            ufw.add(rule)
            print("ADD", rule)
            log_event(ip, "ADD", rule, ip_details)

    thread = Thread(target=task, args=(ip,))
    thread.start()

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO,
                        format='%(asctime)s - %(message)s',
                        datefmt='%Y-%m-%d %H:%M:%S')
    path = sys.argv[1] if len(sys.argv) > 1 else '.'
    event_handler = MyEventHandler(path)
    observer = Observer()
    observer.schedule(event_handler, path, recursive=True)
    observer.start()
    try:
        while True:
            time.sleep(1)
    finally:
        observer.stop()
        observer.join()