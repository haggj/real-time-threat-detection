import json 
from datetime import datetime, timedelta
import pyufw as ufw
import schedule 
import time


def load_honeypot_data():
    '''
        Retrieves all IPs seen within the last two days. 
    '''
    data = []

    # Retrieves the honeypot data from today
    for line in open('/home/cowrie/cowrie/var/log/cowrie/cowrie.json', 'r'):
        data.append(json.loads(line))

    # Retrieves the honeypot data from yesterday
    yesterday = get_yesterday()
    yesterday_file_path = f'/home/cowrie/cowrie/var/log/cowrie/cowrie.json.{yesterday}'
    for line in open(yesterday_file_path, 'r'):
        data.append(json.loads(line))

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


def get_add_delete():
    '''
        Retrieves two lists, one containing IPs to be added, one containing IPs to be deleted from the firewall. 
    '''
    ip_timestamps = load_honeypot_data()
    to_be_added = set()
    to_be_deleted = set()

    now = datetime.now()

    for ip, timestamp in ip_timestamps.items(): 
        datetime_object = datetime.strptime(timestamp, '%Y-%m-%dT%H:%M:%S.%fZ')

        # Checks if the IP has accessed the honeypot within the last 24 hours
        if now-timedelta(hours=24) <= datetime_object <= now: 
            #print(f"ADD RULE: {ip}")
            to_be_added.add(ip)
        else: 
            #print(f"DELETE RULE: {ip}")
            to_be_deleted.add(ip)
    return to_be_added, to_be_deleted


def get_firewall_rules():
    '''
        Retrieves all firewall rules currently active.
    '''
    return ufw.get_rules()


def get_rules_tbd(tbd): 
    '''
        Retrieves the rules which should be deleted.
    '''
    active_rules = get_firewall_rules() 
    to_be_deleted = set()

    # Find the rule numbers of the rules which needs to be deleted
    # University IP is whitelisted 130.208.240.12
    for number, rule in active_rules.items(): 
        if any(ip in rule for ip in tbd if not '130.208.240.12'):
            # todo: check if the ip is the university ip 
            to_be_deleted.add(number)

    before_length = len(tbd)
    after_length = len(to_be_deleted)
    print(f"Out of {before_length} rules to delete, {after_length} were currently active")

    return to_be_deleted


def delete_rules(ips): 
    '''
        Deletes firewall rules based on an input IP list.
    ''' 
    rules = get_rules_tbd(ips)
    for rule in rules: ufw.delete(rule)

def add_rules(ips):
    '''
        Adds firewall rules based on an input IP list. If they're already in the firewall, they won't be duplicated. 
    '''
    for ip in ips: 
        ufw.add(f"deny from {ip} to any port 80")
        ufw.add(f"deny from {ip} to any port 443")

def main(): 
    '''
        Runs the script every 5 minutes.
    '''
    schedule.every(5).minutes.do(update_rules)

    while True: 
        schedule.run_pending()
        time.sleep(1)

def update_rules():
    '''
        Retrieves the IPs seen in the honeypot over the last 24 hours,
        then compares them with the rules currently active on ufw to be able to add and delete them accordingly.   
    '''
    start = time.time()
    add, delete = get_add_delete() 
    delete_rules(delete) 
    add_rules(add)
    end = time.time()
    print("Time:", end - start)

if __name__=="__main__":
    main()