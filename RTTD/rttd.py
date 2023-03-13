import json 
from datetime import datetime, timedelta
import pyufw as ufw
import schedule 
import time

'''
    Retrieves all IPs seen within the last two days. 
'''
def load_honeypot_data():
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

'''
    Retrieves the date of yesterday. 
'''
def get_yesterday(frmt='%Y-%m-%d', string=True):
    yesterday = datetime.now() - timedelta(1)
    if string:
        return yesterday.strftime(frmt)
    return yesterday

'''
    Retrieves two lists, one containing IPs to be added, one containing IPs to be deleted from the firewall. 
'''
def get_add_delete():
    ip_timestamps = load_honeypot_data()
    to_be_added = set()
    to_be_deleted = set()

    now = datetime.now()

    for ip, timestamp in ip_timestamps.items(): 
        datetime_object = datetime.strptime(timestamp, '%Y-%m-%dT%H:%M:%S.%fZ')

        # Checks if the IP has accessed the honeypot within the last 24 hours
        if now-timedelta(hours=24) <= datetime_object <= now: 
            print(f"ADD RULE: {ip}")
            to_be_added.add(ip)
        else: 
            print(f"DELETE RULE: {ip}")
            to_be_deleted.add(ip)
    return to_be_added, to_be_deleted

'''
    Retrieves all firewall rules currently active.
'''
def get_firewall_rules():
    return ufw.get_rules()

'''
    Retrieves the rules which should be deleted.
'''
def get_rules_tbd(tbd): 
    active_rules = get_firewall_rules() 
    to_be_deleted = set()

    # Find the rule numbers of the rules which needs to be deleted 
    for number, rule in active_rules.items(): 
        if any(ip in rule for ip in tbd):
            to_be_deleted.add(number)

    before_length = len(tbd)
    after_length = len(to_be_deleted)
    print(f"Out of {before_length} rules to delete, {after_length} were currently active")

    return to_be_deleted

'''
    Deletes firewall rules based on an input IP list.
''' 
def delete_rules(ips): 
    rules = get_rules_tbd(ips)
    for rule in rules: ufw.delete(rule)

'''
    Adds firewall rules based on an input IP list. If they're already in the firewall, they won't be duplicated. 
'''
def add_rules(ips):
    for ip in ips: ufw.add(f"deny from {ip} to any port 22")

'''
    Runs the script.
    TODO: The script should be run every 5-10 minutes. Run with crontab instead of scheduling? 
'''
def main(): 
    update_rules()

    schedule.every(5).minutes.do(update_rules)

    while True: 
        schedule.run_pending()
        time.sleep(1)

'''
    Retrieves the IPs seen in the honeypot over the last 24 hours,
    then compares them with the rules currently active on ufw to be able to add and delete them accordingly.   
'''
def update_rules():
    add, delete = get_add_delete() 
    delete_rules(delete) 
    add_rules(add)

if __name__=="__main__":
    main()