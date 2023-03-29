# Generates graphs used for the sections I wrote
from pprint import pprint

from charts.chart_generator import PieChart, VerticalBarChart
from logs.rttd_analyzer import RTTDAnalyzer

rttd = RTTDAnalyzer()


def attacks_country():
    by_country = rttd.by_country(top=10)
    VerticalBarChart.render(by_country.keys(), by_country.values(), filename="country.png", show=True)


def attacks_residential():
    by_residential = rttd.by_residential()
    PieChart.render(by_residential.keys(), by_residential.values(), filename="residential.png", show=True)


def attacks_tor():
    by_tor = rttd.by_tor()
    PieChart.render(by_tor.keys(), by_tor.values(), filename="tor.png")


def attacks_blocklist():
    by_blocklist = rttd.by_blocklist()
    PieChart.render(by_blocklist.keys(), by_blocklist.values(), filename="blocklist.png", show=True)


def attacks_port():
    by_ports = rttd.by_ports(top=10)
    VerticalBarChart.render(by_ports.keys(), by_ports.values(), filename="port.png", show=True)

def attacks_port_closed():
    by_ports = rttd.by_ports_closed()
    PieChart.render(by_ports.keys(), by_ports.values(), filename="port_closed.png", show=True)


attacks_port()

data = dict()
for event in rttd._load_events(eventid="ADD"):
    ip = event["src_ip"]
    if ip in data and data[ip] != event["ip_details"]:
        print(f"conflict for {ip}")
    else:
        data[ip] = event["ip_details"]
