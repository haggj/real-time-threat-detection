from charts.chart_generator import PieChart, VerticalBarChart
from logs.http_analyzer import HttpAnalyzer
from logs.https_analyzer import HttpsAnalyzer
from logs.rttd_analyzer import RTTDAnalyzer
from logs.ssh_analyzer import SSHAnalyzer

if __name__=="__main__":

    r = RTTDAnalyzer()
    by_counter = r.by_country(top=3)
    by_residential = r.by_residential()
    print(by_residential)
    PieChart.render(by_residential.keys(), by_residential.values())
    VerticalBarChart.render(by_counter.keys(), by_counter.values())
    print(r.by_country(top=15))

    # exit()

    for service in [SSHAnalyzer(), HttpsAnalyzer(), HttpAnalyzer(), RTTDAnalyzer()]:

        print(service.__class__)
        print("Total connections:\t", service.total_connections())
        print("Connections/day:\t", service.connections_per_day())
        print("Unique IPs:\t\t\t", service.unique_ips())
        print("Returning IPs:\t\t", service.ips_connected_multiple())
        print()