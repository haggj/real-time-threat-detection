import json 
from datetime import datetime, timedelta
import pyufw as ufw

#ufw = ""

def load_honeypot_data():
    # Reading the honeypot data from the json file 
    data = []
    for line in open('/home/cowrie/cowrie/var/log/cowrie/cowrie.json', 'r'):
        data.append(json.loads(line))

    # TODO we need to find yesterdays date, because a new file seems to be added for each day. 
    for line in open('/home/cowrie/cowrie/var/log/cowrie/cowrie.json', 'r'):
        data.append(json.loads(line))


    #print(data)
    # map containing ip as key and timestamp as value 
    ip_timestamps = {}

    for entry in data:
        ip_timestamps[entry['src_ip']] = entry['timestamp']
    print(f"IPs with timestamps: {ip_timestamps}")

    return ip_timestamps

'''
    Retrieves two lists, one containing ips to be added, one containing ips to be deleted from the firewall
'''
def get_add_delete():
    ip_timestamps = load_honeypot_data()
    to_be_added = set()
    to_be_deleted = set()
    print(len(ip_timestamps))
    for k,v in ip_timestamps.items(): 
        ip = k
        timestamp = v
        datetime_object = datetime.strptime(timestamp, '%Y-%m-%dT%H:%M:%S.%fZ')
        now = datetime.now()
        # checks if the ip has accessed the honeypot within the last 24 hours
        if now-timedelta(hours=24) <= datetime_object <= now: 
            print(f"{ip} should be added as a rule")
            to_be_added.add(k)
        else: 
            print(f"{ip} should be deleted as a rule")
            to_be_deleted.add(k)
    print(len(to_be_added))
    return to_be_added, to_be_deleted

'''
    Retrieves firewall rules currently active
'''
def get_firewall_rules():
    return ufw.get_rules()

'''
    Retrieves the rules which should be deleted 
'''
def get_rules_tbd(tbd): 
    active_rules = get_firewall_rules() 
    print(active_rules)
    print(tbd)

    to_be_deleted = set()
    # Find the numbers of the rules which needs to be deleted 
    for number, rule in active_rules.items(): 
        if any(ip in rule for ip in tbd):
            print("")
            to_be_deleted.add(number)

    return to_be_deleted

'''
    Deletes firewall rules based on an input IP list.
''' 
def delete_rules(ips): 
    rules = get_rules_tbd(ips)
    for rule in rules: 
        ufw.delete(rule)

'''
    Adds firewall rules based on an input IP list. If they're already in the firewall, they won't be duplicated. 
'''
def add_rules(ips):
    for ip in ips: 
        ufw.add(f"deny from {ip} to any port 22")

'''
    Runs the script
    TODO: The script should be run every 5-10 minutes or so! 
'''
def main(): 
    add, delete = get_add_delete() 
    delete_rules(delete) 
    add_rules(add)

if __name__=="__main__":
    main()