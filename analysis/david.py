from charts.chart_generator import PieChart, VerticalBarChart, ScatterChart
from logs.http_analyzer import HttpAnalyzer
from logs.https_analyzer import HttpsAnalyzer
from logs.rttd_analyzer import RTTDAnalyzer
from logs.ssh_analyzer import SSHAnalyzer
from datetime import datetime
import pandas as pd
import matplotlib.pyplot as plt
import numpy as np


def connections_to_ports():

    s = SSHAnalyzer(datetime.strptime('22-03-2023', '%d-%m-%Y'), datetime.strptime('27-03-2023', '%d-%m-%Y'))
    r = RTTDAnalyzer(datetime.strptime('22-03-2023', '%d-%m-%Y'), datetime.strptime('27-03-2023', '%d-%m-%Y'))

    # phase 1
    #http1 = HttpAnalyzer(datetime.strptime('10-03-2023', '%d-%m-%Y'), datetime.strptime('15-03-2023', '%d-%m-%Y'))
    #https1 = HttpsAnalyzer(datetime.strptime('10-03-2023', '%d-%m-%Y'), datetime.strptime('15-03-2023', '%d-%m-%Y'))

    # phase 2
    http = HttpAnalyzer(datetime.strptime('22-03-2023', '%d-%m-%Y'), datetime.strptime('27-03-2023', '%d-%m-%Y'))
    https = HttpsAnalyzer(datetime.strptime('22-03-2023', '%d-%m-%Y'), datetime.strptime('27-03-2023', '%d-%m-%Y'))

    # port 80 without firewall to port 80 with firewall
    # i.e. port 80 during stage 1 and port 80 during stage 2
    def port_80():
        print("http phase 1:")
        print("Total connections:\t", http.total_connections())
        print("Connections/day:\t", http.connections_per_day())
        print("Unique IPs:\t\t\t", http.unique_ips())
        print("Returning IPs:\t\t", http.ips_connected_multiple())

        

    # maybe also check if the ips align with the ones in the firewall?? 
    # but they should do so does that really make sense
    def port_443():
        print("https phase 1:")
        print("Total connections:\t", https.total_connections())
        print("Connections/day:\t", https.connections_per_day())
        print("Unique IPs:\t\t\t", https.unique_ips())
        print("Returning IPs:\t\t", https.ips_connected_multiple())

def same_ips(ip_1: list, ip_2: list):
    common_ips = []
    for ip in ip_1:
        if ip in ip_2:
            common_ips.append(ip)
    return common_ips

def firewall_efficiency():
    ssh_ips_timestamps = s.timestamps_per_ip()
    rttd_ips_timestamps = r.timestamps_per_ip()

    deltas = []

    for ip, timestamps in rttd_ips_timestamps.items():
        rttd_timestamp = timestamps[0]
        ssh_timestamp = ssh_ips_timestamps[ip][0]
        #print(timestamps)
        delta = rttd_timestamp - ssh_timestamp
        if delta != 0: 
            print(f'Difference is {delta.microseconds} ms')
            deltas.append(delta.microseconds)
    
    print(sum(deltas) / len(deltas))

def compare_ports(same_ips, port1, port2): 
    port1_ips_timestamps = timestamps_and_ips[port1]
    port2_ips_timestamps = timestamps_and_ips[port2]

    port1_ips = {key: port1_ips_timestamps[key] for key in same_ips}
    port2_ips = {key: port2_ips_timestamps[key] for key in same_ips}


    new_dict = {}
    x_timestamps_port1 = []
    y_ips_port1 = []
    x_timestamps_port2 = []
    y_ips_port2 = []

    for k, v in port1_ips.items():
        if isinstance(v, list):
            for timestamp in v:
                x_timestamps_port1.append(timestamp)
                y_ips_port1.append(k)
        else:
            x_timestamps_port1.append(v)
            y_ips_port1.append(k)
        
    for k, v in port2_ips.items():
        if isinstance(v, list):
            for timestamp in v:
                x_timestamps_port2.append(timestamp)
                y_ips_port2.append(k)
        else:
            x_timestamps_port2.append(v)
            y_ips_port2.append(k)

    fig, ax = plt.subplots()
    ax.scatter(x_timestamps_port1, y_ips_port1, label=port1)
    ax.scatter(x_timestamps_port2, y_ips_port2, label=port2)
    #ax.locator_params(axis='x', nbins=30)
    ax.tick_params(axis='x', labelrotation=90)   
    ax.legend()
    ax.grid(True)
    plt.show()

def port_analysing():
    tc = []
    cpd = []
    uip = []
    ipm = []
    all_ips = []
    most_ip = []
    timestamps_and_ips = {}
    labels = ['http', 'https', 'ssh']
    i = 0
    for service in [HttpAnalyzer(), HttpsAnalyzer(), SSHAnalyzer()]:
        print(service.__class__)
        #print("Total connections:\t", service.total_connections())
        #tc.append(service.total_connections())
        #print("Connections/day:\t", service.connections_per_day())
        #cpd.append(service.connections_per_day())
        #print("Unique IPs:\t\t\t", service.unique_ips())
        #uip.append(service.unique_ips())
        #print("Returning IPs:\t\t", service.ips_connected_multiple())
        #ipm.append(service.ips_connected_multiple())
        timestamps_ips = service.timestamps_per_ip()
        all_ips.append(list(timestamps_ips.keys()))
        if i == 0: 
            #print("http")
            #print(timestamps_ips)
            timestamps_and_ips['http'] = timestamps_ips
        if i == 1:
            timestamps_and_ips['https'] = timestamps_ips
        else: 
            #print("ssh")
            #print(timestamps_ips)
            timestamps_and_ips['ssh'] = timestamps_ips

        most_ip.append(service.get_most_connecting_ip())
        i+=1

    # # Connections distribution for connections per day
    # PieChart.render(labels, cpd, show=True, filename='1_1.png')
    # # Connections distribution for unique connections
    # PieChart.render(labels, uip, show=True, filename='1_2.png')

    # ## Check If Ips connect to multiple ports
    # # compare http & https
    same_http_https = same_ips(all_ips[0], all_ips[1])
    print('same_http_https: ', len(same_http_https))

    compare_ports(same_http_https, "http", "https")
    # # compare http & ssh
    same_http_ssh = same_ips(all_ips[0], all_ips[2])
    print('same_http_ssh: ', len(same_http_ssh))

    compare_ports(same_http_ssh, "http", "ssh")

    #for ip, timestamps in http_ips.items():
    #    new_dict[ip] = {"http": timestamps, "ssh": ssh_ips[ip]}

    #print("HTTP", http_ips)
    #print("SSH", ssh_ips)
    
    #for key, value in new_dict.items():
    #    print(key)
   #     print(value)
    #    print("\n")

    # # compare https & ssh
    same_https_ssh = same_ips(all_ips[1], all_ips[2])
    print('same_https_ssh: ', len(same_https_ssh))

    compare_ports(same_https_ssh, "https", "ssh")

    # # compare http, https & ssh
    same_all = same_ips(same_http_https, same_https_ssh)
    print('same_all: ', len(same_all))


if __name__=="__main__":
    http = HttpsAnalyzer()
    timestamps_action_per_ip = http.timestamps_action_per_ip()
    http_returning_ips = [ip for ip, connections in http.timestamps_per_ip().items() if len(connections) != 1]

    # filter based on returning ips     
    relevant_data = {key: timestamps_action_per_ip[key] for key in http_returning_ips}

    i = 0
    for k in sorted(relevant_data, key=lambda k: len(relevant_data[k]), reverse=True):
        if i < 20:
            print(k)
        i += 1

    for k, v in relevant_data.items():
        print(k)
        if isinstance(v, list):
            for i in v:
                print(i)
        #else:
        #   print(v)
        print("\n")

    #print(timestamps_action_per_ip)
    
    
    https = HttpsAnalyzer()
    https_returning_ips = [ip for ip, connections in https.timestamps_per_ip().items() if len(connections) != 1]
#firewall_efficiency()

##port_80()

#port_443()

#rule_additions, rule_additions_a_day = r.rule_additions()
#rule_deletions, rule_deletions_a_day = r.rule_deletions()
#nbr_of_never_deleted = r.nbr_of_never_deleted()

#print("Total rule additions:\t\t", rule_additions)
#print("Rule additions/day:\t\t", rule_additions_a_day)
#print("Total rule deletions:\t\t", rule_deletions)
#print("Rule deletions/day:\t\t", rule_deletions_a_day)
#print("Rules never deleted:\t\t", nbr_of_never_deleted)

