from charts.chart_generator import PieChart, VerticalBarChart
from logs.http_analyzer import HttpAnalyzer
from logs.https_analyzer import HttpsAnalyzer
from logs.rttd_analyzer import RTTDAnalyzer
from logs.ssh_analyzer import SSHAnalyzer

if __name__=="__main__":

    #for service in [SSHAnalyzer(), HttpsAnalyzer(), HttpAnalyzer(), RTTDAnalyzer()]:
    for service in [SSHAnalyzer(),RTTDAnalyzer()]:
        print(service.__class__)
        print("Total connections:\t", service.total_connections())
        print("Connections/day:\t", service.connections_per_day())
        print("Unique IPs:\t\t\t", service.unique_ips())
        print("Returning IPs:\t\t", service.ips_connected_multiple())
        print()

    r = RTTDAnalyzer()
    #by_counter = r.by_country(top=15)
    #by_residential = r.by_residential()
    rule_additions, rule_additions_a_day = r.rule_additions()
    rule_deletions, rule_deletions_a_day = r.rule_deletions()

    print("Total rule additions:\t\t", rule_additions)
    print("Rule additions/day:\t\t", rule_additions_a_day)
    print("Total rule deletions:\t\t", rule_deletions)
    print("Rule deletions/day:\t\t", rule_deletions_a_day)

    #PieChart.render(by_residential.keys(), by_residential.values())
    #VerticalBarChart.render(by_counter.keys(), by_counter.values())
