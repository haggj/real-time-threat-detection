import json 
from datetime import datetime, timedelta
import pyufw as ufw
import schedule 
import time

'''
    Script that runs every 5-10 minutes. 
    Deletes blockings of IP addresses from ufw after they have not been seen in the honeypot for 24 hours.
    Runs checks of all IPs.
'''

WHITELISTED_IPS = ['130.208.240.12', '85.220.40.135']

def load_honeypot_data(path):
    '''
        Retrieves all IPs seen within the last two days. 
    '''
    data = []

    # Retrieves the honeypot data from today
    for line in open(path, 'r'):
        data.append(json.loads(line))

    # Retrieves the honeypot data from yesterday
    yesterday = get_yesterday()
    #yesterday_file_path = f'{path}.{yesterday}'
    #for line in open(yesterday_file_path, 'r'):
    #    data.append(json.loads(line))

    # Dictionary containing IPs as keys and timestamps as values
    ip_timestamps = {}

    for entry in data: ip_timestamps[entry['src_ip']] = entry['timestamp']

    return ip_timestamps


def get_yesterday(frmt='%Y-%m-%d', string=True):
    '''
        Retrieves the date of yesterday. 
    '''
    yesterday = datetime.now() - timedelta(1)
    if string:
        return yesterday.strftime(frmt)
    return yesterday


def get_delete():
    '''
        Retrieves a list containing IPs to be deleted from the firewall. 
    '''
    ip_timestamps = load_honeypot_data('/app/ru-sec-project/RTTD/test_delete.txt')
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


def get_firewall_rules():
    '''
        Retrieves all firewall rules currently active.
    '''
    return ufw.get_rules()


def get_rules_tbd(tbd): 
    '''
        Retrieves the rules which should be deleted by cross-referencing the honeypot data with the active ufw rules.
    '''
    active_rules = get_firewall_rules() 
    to_be_deleted = set()

    # Find the rule numbers of the rules which needs to be deleted
    for number, rule in active_rules.items(): 
        if any((x:=ip) in rule for ip in tbd if ip not in WHITELISTED_IPS):
            # todo: check if the ip is the university ip 
            to_be_deleted.add((x, number, rule))
        
    return to_be_deleted

def delete_rules(ips): 
    '''
        Deletes firewall rules based on an input IP list.
    ''' 
    rules = get_rules_tbd(ips)
    all_rules = get_firewall_rules()
    for rule in rules: 
        ufw.delete(rule[2])
        print("DELETE:", rule[2])
        log_event(rule[0], "DELETE", rule[2])

def update_rules():
    '''
        Retrieves the IPs seen in the honeypot over the last 24 hours,
        then compares them with the rules currently active on ufw to be able to add and delete them accordingly.   
    '''
    start = time.time()
    delete = get_delete() 
    delete_rules(delete) 
    end = time.time()
    print("Time elapsed:", end - start)

def log_event(ip, event, rule):
    '''
        Logs an event. 
    '''
    timestamp = datetime.now()
    res = f"""{{"src_ip": "{ip}", "event": "{event}", "rule": "{rule}", "timestamp": "{timestamp}"}}\n"""
    with open('log/rttd_logs.txt', 'a') as f:
        f.write(res)
    f.close()

def main(): 
    '''
        Runs the script every 5 minutes.
    '''
    update_rules()
    schedule.every(5).minutes.do(update_rules)

    while True: 
        schedule.run_pending()
        time.sleep(1)

if __name__=="__main__":
    main()