import sys
import time
import logging
from threading import Thread
from watchdog.observers import Observer
from watchdog.events import LoggingEventHandler, FileSystemEventHandler
import pyufw as ufw
import json
from datetime import datetime, timedelta
from collections import defaultdict
import schedule
from ip_analyzer import IpAnalyzer
import os
import yaml

'''
    Script that runs based on updates of the cowrie logs. 
    Blocks IP addresses, idea is to make it as much in real-time as possible.
'''

WHITELISTED_IPS = ['130.208.240.12', '85.220.40.135']
#WHITELISTED_IPS = []
cached_rules = defaultdict(list)

def update_cached_rules():
    '''
        Updates the cached rules through retrieving the current firewall rules.
    '''
    print("------------- CACHING RULES -------------")
    print("timestamp:", datetime.now())

    start = time.time()

    rules = ufw.get_rules()

    cached_rules.clear()


    for number, rule in rules.items(): 
        split = rule.split(" ")
        cached_rules[split[2]] = number

    end = time.time()
    print("Time elapsed:", end - start)
    print("--------- UPDATED CACHED RULES ----------\n")


class MyEventHandler(FileSystemEventHandler):
    '''
        Handles events using Watchdog. 
    '''

    def __init__(self):
        self.last_ip = ""

    def on_modified(self, event):
        '''
            Called whenever a file is modified.
        '''
        print("--------------- NEW MODIFICATION --------------")

        print("File modified, timestamp:", datetime.now())
        path =  event.src_path
        print("path:", path)
        if path == '/home/cowrie/cowrie/var/log/cowrie/cowrie.json':
            handle_new_event(path)
        else:
            print("Ignored path:", path)
        print("-----------------------------------------\n")

def handle_new_event(path):

    start = time.time()
    ip = load_last_event(path) # Grabs the IP
    print("Accessed IP: ", ip)

    # Check IP against cached rules 
    if ip and ip not in cached_rules and ip not in WHITELISTED_IPS:
        rules = add_rules(ip) # Blocks the ip from ufw
        cached_rules[ip] = []
        print("Added to rules.")
    else:
        print("Already blocked.")
    end = time.time()
    print("Time elapsed:", end - start)


def log_event(ip, event, rule, ip_details, timestamp):
    """
        Logs an event. 
    """
    data = {
        "timestamp": str(timestamp),
        "src_ip": ip,
        "event": event,
        "rule": rule,
        "ip_details": ip_details
    }
    with open('log/rttd_logs.txt', 'a') as f:
        f.write(json.dumps(data) + "\n")
    f.close()
    print("Saved log\n")

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
        for rule in rules:
            ufw.add(rule)
            print("ADD", rule, "\n")
        timestamp = datetime.now()
        ip_details = IpAnalyzer().run(ip)
        for rule in rules:
            log_event(ip, "ADD", rule, ip_details, timestamp)

    thread = Thread(target=task, args=(ip,))
    thread.start()


def cleanup():
    print("---------------- CLEANUP ----------------")
    print("timestamp:", datetime.now())
    start = time.time()

    ip_timestamps = load_honeypot_data('/home/cowrie/cowrie/var/log/cowrie/cowrie.json')
    ips_24hours = get_ips_last_24hours(ip_timestamps)
    ips_to_be_deleted = get_rules_tbd(ips_24hours)
    delete_rules(ips_to_be_deleted)

    end = time.time()
    print(f"Deleted {len(ips_to_be_deleted)} rules")
    print("Time elapsed:", end - start)
    print("------------- CLEANED RULES -------------\n")

def load_honeypot_data(path):
    '''
        Retrieves all IPs seen within the last two days. 
    '''
    data = []

    # Retrieves the honeypot data from today
    with open(path, 'r') as f:
        for line in f: 
            data.append(yaml.safe_load(line))

    # Retrieves the honeypot data from yesterday
    yesterday = get_date_of_yesterday()
    yesterday_file_path = f'{path}.{yesterday}'
    if os.path.isfile(yesterday_file_path):
        print(f"{yesterday_file_path} exists.")
        with open(yesterday_file_path, 'r') as f:
            for line in f:
                data.append(json.loads(line))

    # Dictionary containing IPs as keys and timestamps as values
    ip_timestamps = {}

    for entry in data: ip_timestamps[entry['src_ip']] = entry['timestamp']

    return ip_timestamps


def get_date_of_yesterday(frmt='%Y-%m-%d', string=True):
    '''
        Retrieves the date of yesterday. 
    '''
    yesterday = datetime.now() - timedelta(1)
    if string:
        return yesterday.strftime(frmt)
    return yesterday


def get_ips_last_24hours(ip_timestamps):
    '''
        Retrieves a list containing IPs to be deleted from the firewall. 
    '''
    to_be_deleted = set()
    now = datetime.now()

    for ip, timestamp in ip_timestamps.items(): 
        datetime_object = datetime.strptime(timestamp, '%Y-%m-%dT%H:%M:%S.%fZ')

        # Checks if the IP has accessed the honeypot within the last 24 hours
        if now-timedelta(hours=24) <= datetime_object <= now: 
            pass
        else: 
            to_be_deleted.add(ip)
    return to_be_deleted


def get_rules_tbd(tbd): 
    '''
        Retrieves the rules which should be deleted by cross-referencing the honeypot data with the active ufw rules.
    '''
    active_rules = ufw.get_rules()
    to_be_deleted = set()

    # Find the rule numbers of the rules which needs to be deleted
    for number, rule in active_rules.items(): 
        if any((x:=ip) in rule for ip in tbd if ip not in WHITELISTED_IPS):
            # todo: check if the ip is the university ip 
            to_be_deleted.add((x, number, rule))
        
    return to_be_deleted

def delete_rules(rules): 
    '''
        Deletes firewall rules based on an input IP list.
    ''' 
    for rule in rules: 
        ufw.delete(rule[2])
        print("DELETE:", rule[2])
        log_event(rule[0], "DELETE", rule[2], {}, datetime.now())

def reset_firewall():
    print("------------ RESET FIREWALL -------------")
    ufw.reset()
    ufw.enable() 
    ufw.default(incoming='allow', outgoing='allow', routed='reject')
    ufw.set_logging('low')
    print(ufw.status())    
    print("-----------------------------------------\n")


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO,
                        format='%(asctime)s - %(message)s',
                        datefmt='%Y-%m-%d %H:%M:%S',
                        filename="watchdog_log.txt")
    #path = sys.argv[1] if len(sys.argv) > 1 else '/home/cowrie/cowrie/var/log/cowrie/'
    path = '/home/cowrie/cowrie/var/log/cowrie/'

    event_handler = MyEventHandler()
    logging_handler = LoggingEventHandler()
    observer = Observer()
    observer.schedule(event_handler, path, recursive=True)
    observer.schedule(logging_handler, path, recursive=True)
    observer.start()
    schedule.every(5).minutes.do(update_cached_rules)
    schedule.every(10).minutes.do(cleanup)

    api_key = os.environ.get('IPHUB_KEY', None)
    if not api_key:
        raise Exception("Missing environment variable: IPHUB_KEY")
    #reset_firewall()
    cleanup()
    update_cached_rules()

    try:
        while True:
            schedule.run_pending()
            time.sleep(1)

            # check time treshold, if reached a certain time then update cache 
    finally:
        observer.stop()
        observer.join()
