import json
import os
from datetime import timedelta, datetime
from typing import Dict, List, Tuple
from ip_analyzer import IpAnalyzer

from dateutil import parser

start = datetime.strptime('22-03-2023', '%d-%m-%Y')
end = datetime.strptime('27-03-2023', '%d-%m-%Y')
whitelisted_ips = ['130.208.240.12', '85.220.40.135', '129.187.205.52', '129.187.207.88']


log_folder = "productive_logs/cowrie"

def log_files():
    """
    Returns all log files for the defined time frame.
    """
    log_files = []
    delta = end - start
    for i in range(delta.days):
        day = start + timedelta(days=i)
        formatted_day = day.strftime("%Y-%m-%d")
        file = f"{log_folder}/cowrie.json.{formatted_day}"
        if os.path.isfile(file):
            log_files.append(file)
    print(log_files)
    return log_files

def load_by_eventid(eventid):
    """
    Loads all events of the specified eventid during time frame.
    """
    for log_file in log_files():
        with open(log_file, "r") as f:
            lines = f.readlines()

        for line in lines:
            event = json.loads(line)
            ip = event["src_ip"]
            timestamp = parser.parse(event["timestamp"]).replace(tzinfo=None)

            if event["eventid"] != eventid:
                continue

            if ip not in whitelisted_ips and start <= timestamp <= end:
                yield event

def timestamps_per_ip() -> Dict[str, List[datetime]]:
    data = dict()

    events = load_by_eventid("cowrie.session.connect")
    for event in events:
        timestamp = parser.parse(event["timestamp"]).replace(tzinfo=None)
        ip = event["src_ip"]

        if ip in data:
            data[ip].append(timestamp)
        else:
            data[ip] = [timestamp]

    return data


active_firewall_rules = dict()

# ip: last seen 
cached_rules = {}
current_time = None

seen_ips = {}
seen_ips_multiple = {}




def fix(ip_details):
    events = load_by_eventid("cowrie.session.connect")
    i = 0
    for event in events:
        current_time = datetime.strptime(event['timestamp'], '%Y-%m-%dT%H:%M:%S.%fZ')

        ip = event["src_ip"]
        # if IP in cache 
        # -> Skip
        if ip in cached_rules:
            continue
        # if IP not in cache 
        # -> add to firewall rule, add to cache
        else: 
            print("ADDING", ip)
            timestamp = event["timestamp"]
            active_firewall_rules[ip] = timestamp
            cached_rules[ip] = timestamp
            seen_ips[ip] = timestamp

            datetime_object = datetime.strptime(timestamp, '%Y-%m-%dT%H:%M:%S.%fZ')

            if ip in seen_ips_multiple:
                seen_ips_multiple[ip].append(timestamp)
            else:
                seen_ips_multiple[ip] = [timestamp]
            if ip in ip_details:
                details = ip_details[ip]
            else:
                details = IpAnalyzer().run(ip)

            log_event(ip, "ADD", datetime_object, details)
            
        # if not seen within 24 hours 
        # -> Delete, remove from cache 
        # go over the cached rules 
        if i == 50:
            cleanup(current_time)
            i=0
        i+=1
        
    return cached_rules

def cleanup(current_time):
    to_be_deleted = set()
    for ip, timestamp in seen_ips.items(): 
        datetime_object = datetime.strptime(timestamp, '%Y-%m-%dT%H:%M:%S.%fZ')

        if current_time-timedelta(hours=24) <= datetime_object <= current_time: 
            pass
        else: 
            if ip in active_firewall_rules:
                to_be_deleted.add(ip)
    
    #print("DELETING", to_be_deleted)
    for ip in to_be_deleted:
        addition_timestamp = active_firewall_rules.pop(ip)
        #deletion_timestamp = timestamp + timedelta(hours=24)
        print("DELETED", ip)
        log_event(ip, "DELETE", current_time, [])

        if ip in cached_rules: 
            cached_rules.pop(ip)
            print("REMOVED FROM CACHE", ip)

    #print(active_firewall_rules)

def unique_ips() -> int:
    """
    Number of unique IPs which connected during time frame.
    """
    return len(seen_ips_multiple)

def ips_connected_once() -> int:
    """
    Number of IPs which connected only once during time frame.
    """
   
    return  unique_ips() - len(ips_connected_multiple())

def ips_connected_multiple() -> List[Tuple[str, List[datetime]]]:
    """
    Number of IPs which connected multiple times during time frame.
    """
    return [ip for ip, connections in seen_ips_multiple.items() if len(connections) != 1]
    
def log_event(ip, event, timestamp, ip_details):
    """
        Logs an event. 
    """
    data = {
        "timestamp": str(timestamp),
        "src_ip": ip,
        "event": event,
        "ip_details": ip_details
    }
    with open('fix_rttd_logs.txt', 'a') as f:
        f.write(json.dumps(data) + "\n")
    f.close()
    #print("Saved log\n")

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

#log_files()
#print(timestamps_per_ip())
#print(fix())


log_file_old_rttd = "productive_logs/rttd_phase2"
#log_file = "fix_rttd_logs.txt"
def old_rttd_load_events(eventid=None):
    with open(log_file_old_rttd, "r") as f:
        lines = f.readlines()
    
    here_start = datetime.strptime('20-03-2023', '%d-%m-%Y')
    here_end = datetime.strptime('27-03-2023', '%d-%m-%Y')       

    for line in lines:
        event = json.loads(line)
        ip = event["src_ip"]
        timestamp = parser.parse(event["timestamp"]).replace(tzinfo=None)

        if eventid and event["event"] != eventid:
            continue

        if ip not in whitelisted_ips and here_start <= timestamp <= here_end:
            yield event



# {"timestamp": "2023-03-22 00:03:39.366997", "src_ip": "110.182.219.152", "event": "ADD", "rule": "deny from 110.182.219.152 to any port 80", "ip_details": {"blocklist-level1": false, "blocklist-level2": false, "tor-exit-node": false, "geo": {"country": "China", "city": "Taiyuan", "lat": 37.7953, "lon": 112.567}, "iphub": {"hostname": "110.182.219.152", "isp": "CHINANET-BACKBONE", "block": 0}, "open-ports": []}}
# need to retrieve ip-details

def old_rttd_get_ip_details():
    old_rttd_logs_ip_events = {}

    events = old_rttd_load_events(eventid="ADD")
    for event in events:
        ip = event["src_ip"]
        ip_details = event['ip_details']

        old_rttd_logs_ip_events[ip] = ip_details

    #print(data)
    return old_rttd_logs_ip_events

ip_details = old_rttd_get_ip_details()

fix(ip_details)

print("Unique", unique_ips())
print("ips once", ips_connected_once())
multiple = ips_connected_multiple()
print("ips multiple", len(multiple), "\n", multiple)

