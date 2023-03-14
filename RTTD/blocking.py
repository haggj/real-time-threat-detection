import sys
import time
import logging
from watchdog.observers import Observer
from watchdog.events import LoggingEventHandler, FileSystemEventHandler
import pyufw as ufw
import json
from datetime import datetime, timedelta
from collections import defaultdict
import schedule

'''
    Script that runs based on updates of the cowrie logs. 
    Blocks IP addresses, idea is to make it as much in real-time as possible.
'''

WHITELISTED_IPS = ['130.208.240.12', '85.220.40.135']

cached_rules = defaultdict(list)

def update_cached_rules():
    '''
        Updates the cached rules through retrieving the current firewall rules.
    '''
    rules = ufw.get_rules()

    for number, rule in rules.items(): 
        split = rule.split(" ")
        cached_rules[split[2]].append(number)
    
    print("UPDATED CACHED RULES\n")

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
        start = time.time()
        ip = load_last_event(self.path) # Grabs the IP
        print("IP", ip)

        # Check IP against cached rules 
        if cached_rules.get(ip) != None and ip not in WHITELISTED_IPS:
            rules = add_rules(ip) # Blocks the ip from ufw

        end = time.time()
        print("Time elapsed:", end - start, "\n")


def log_event(ip, event, rule):
    '''
        Logs an event. 
    '''
    timestamp = datetime.now()
    res = f"""{{"src_ip": "{ip}", "event": "{event}", "rule": "{rule}", "timestamp": "{timestamp}"}}\n"""
    with open('log/rttd_logs.txt', 'a') as f:
        f.write(res)
    f.close()

def call_analyzer():
    # add after rule 
    #call_analyser
    #logs everything 
    pass

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
    '''
        Adds firewall rules based on an input IP. If it's already in the firewall, it won't be duplicated. 
    '''
    rules = [f"deny from {ip} to any port 80", f"deny from {ip} to any port 443"]
    for rule in rules: 
        ufw.add(rule)
        print("ADD", rule)
        log_event(ip, "ADD", rule)
    return rules

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO,
                        format='%(asctime)s - %(message)s',
                        datefmt='%Y-%m-%d %H:%M:%S')
    path = sys.argv[1] if len(sys.argv) > 1 else '.'
    event_handler = MyEventHandler(path)
    observer = Observer()
    observer.schedule(event_handler, path, recursive=True)
    observer.start()
    schedule.every(1).minutes.do(update_cached_rules)

    try:
        while True:
            schedule.run_pending()
            time.sleep(1)

            # check time treshold, if reached a certain time then update cache 
    finally:
        observer.stop()
        observer.join()