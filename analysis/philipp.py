from charts.chart_generator import PieChart, VerticalBarChart, LineChart
from logs.http_analyzer import HttpAnalyzer
from logs.https_analyzer import HttpsAnalyzer
from logs.rttd_analyzer import RTTDAnalyzer
from logs.ssh_analyzer import SSHAnalyzer
import math

def same_ips(ip_1: list, ip_2: list):
    common_ips = []
    for ip in ip_1:
        if ip in ip_2:
            common_ips.append(ip)
    return common_ips

if __name__=="__main__":
    tc = []
    cpd = []
    uip = []
    ipm = []
    all_ips = []
    most_ip = []
    labels = ['http', 'https', 'ssh']
    for service in [HttpAnalyzer(), HttpsAnalyzer(), SSHAnalyzer()]:
        print(service.__class__)
        print("Total connections:\t", service.total_connections())
        tc.append(service.total_connections())
        print("Connections/day:\t", service.connections_per_day())
        cpd.append(service.connections_per_day())
        print("Unique IPs:\t\t\t", service.unique_ips())
        uip.append(service.unique_ips())
        print("Returning IPs:\t\t", service.ips_connected_multiple())
        ipm.append(service.ips_connected_multiple())
        all_ips.append(list(service.timestamps_per_ip().keys()))
        most_ip.append(service.get_most_connecting_ip())
        print()

    # # Connections distribution for connections per day
    # PieChart.render(labels, cpd, show=True, filename='1_1.png')
    # # Connections distribution for unique connections
    # PieChart.render(labels, uip, show=True, filename='1_2.png')

    # ## Check If Ips connect to multiple ports
    # # compare http & https
    # same_http_https = same_ips(all_ips[0], all_ips[1])
    # print('same_http_https: ', len(same_http_https))
    # # compare http & ssh
    # same_http_ssh = same_ips(all_ips[0], all_ips[2])
    # print('same_http_ssh: ', len(same_http_ssh))
    # # compare https & ssh
    # same_https_ssh = same_ips(all_ips[1], all_ips[2])
    # print('same_https_ssh: ', len(same_https_ssh))
    # # compare http, https & ssh
    # same_all = same_ips(same_http_https, same_https_ssh)
    # print('same_all: ', len(same_all))
    # # # Output Stage 2
    # # same_http_https: 26
    # # same_http_ssh: 10
    # # same_https_ssh: 24
    # # same_all: 5
    # # # Output Stage 1
    # # same_http_https: 0
    # # same_http_ssh: 0
    # # same_https_ssh: 17
    # # same_all: 0

    # ## Check if IPs connect multiple times
    # # pie chart for each
    # for i in range(3):
    #     lab = ['unique_ips-' + labels[i], 'returning_ips-' + labels[i]]
    #     data = [uip[i], ipm[i]]
    #     fn = '3_' + str(i) + '.png'
    #     PieChart.render(lab, data, show=True, filename=fn)
    # # bar chart for percent of all
    # data = []
    # for i in range(3):
    #     data.append(math.ceil((ipm[i]/uip[i]) * 100))
    # VerticalBarChart.render(labels, data, filename='3_4.png', show=True)

    ## Plot most connecting ip for each port
    #LineChart.render(labels, most_ip, filename='3_5.png', show=True)
    print(most_ip)