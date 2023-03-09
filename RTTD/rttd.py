import json 
from datetime import datetime, timedelta
#import pyufw as ufw

ufw = ""

def load_honeypot_data():
    # Reading the honeypot data from the json file 
    data = []
    for line in open("../honeypot/log/example_cowrie.json", 'r'):
        data.append(json.loads(line))

    #print(data)
    # map containing ip as key and timestamp as value 
    ip_timestamps = {}

    for entry in data:
        ip_timestamps[entry['src_ip']] = entry['timestamp']
    print(f"IPs with timestamps: {ip_timestamps}")

    return ip_timestamps

'''
Python function to get all rules to create and all rules to delete

    create: all incoming connections from the last 24 hours
    delete: all the ones that has not been seen during the last 24 hours

'''

# returns two lists, one containing ips to be added, one containing ips to be deleted from the firewall
def get_add_delete():
    ip_timestamps = load_honeypot_data()
    to_be_added = []
    to_be_deleted = []

    for k,v in ip_timestamps.items(): 
        ip = k
        timestamp = v
        datetime_object = datetime.strptime(timestamp, '%Y-%m-%dT%H:%M:%S.%fZ')
        now = datetime.now()
        # checks if the ip has accessed the honeypot within the last 24 hours
        if now-timedelta(hours=24) <= datetime_object <= now: 
            print(f"{ip} should be added as a rule")
            to_be_added.append(k)
        else: 
            print(f"{ip} should be deleted as a rule")
            to_be_deleted.append(k)
    return to_be_added, to_be_deleted

# Retrieves current firewall rules
def get_firewall_rules():
    return ufw.get_rules()

# Deletes firewall rules based on an input IP list 
def delete_rules(ips): 
    #current_rules = get_firewall_rules()
    '''
        TODO not sure if this works, also not sure if this is how we want it to work if it is. 
        Another way would be to delete all firewall rules, then add the new ones.
        A third way would be to check the rules against the current rules in the firewall? 
    '''
    for ip in ips: 
        ufw.delete(f"deny from {ip} to any comment '{ip}'")

# Adds firewall rules based on an input IP list 
def add_rules(ips):
    # ufw deny from {IP} to any {port} comment 'This is a comment'
    '''
        TODO: What if the rule is already in the firewall? 
    '''
    for ip in ips: 
        ufw.add(f"deny from {ip} to any comment '{ip}'")

# Runs the script
def main(): 
    add, delete = get_add_delete() 

    #delete_rules(delete)
    #add_rules(add)

if __name__=="__main__":
    main()