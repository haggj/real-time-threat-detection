import json
import socket
from datetime import datetime
from typing import Dict, List

from dateutil import parser

from charts.chart_generator import PieChart, VerticalBarChart
from logs.abstract_analyzer import AbstractAnalyzer


class RTTDAnalyzer(AbstractAnalyzer):
    log_file = "productive_logs/simulated_rttd_phase2"

    def _load_events(self, eventid=None, unique_ips=True):
        with open(self.log_file, "r") as f:
            lines = f.readlines()

        cache = dict()
        for line in lines:
            event = json.loads(line)
            ip = event["src_ip"]
            timestamp = parser.parse(event["timestamp"]).replace(tzinfo=None)

            if eventid and event["event"] != eventid:
                continue

            if ip not in self.whitelisted_ips and self.start <= timestamp <= self.end:
                if ip not in cache:
                    cache[ip] = True
                    yield event

    def by_country(self, top=None):
        data = dict()
        for event in self._load_events(eventid="ADD"):
            country = event["ip_details"]["geo"]["country"]
            data[country] = data.setdefault(country, 0) + 1
        data = dict(sorted(data.items(), reverse=True, key=lambda item: item[1]))
        if top:
            top_data = dict()
            for key, value in list(data.items())[:top]:
                top_data[key] = value
            top_data["Others"] = 0
            for value in list(data.values())[top:]:
                top_data["Others"] += value
            return top_data

        return data

    def by_residential(self):
        data = dict()
        for event in self._load_events(eventid="ADD"):
            if event["ip_details"]["iphub"]["block"] == 0:
                key = "Residential IPs"
                data[key] = data.setdefault(key, 0) + 1
            else:
                key = "Data center IPs"
                data[key] = data.setdefault(key, 0) + 1
        return data

    def by_tor(self):
        data = dict()
        for event in self._load_events(eventid="ADD"):
            if event["ip_details"]["tor-exit-node"]:
                key = "TOR exit node"
                data[key] = data.setdefault(key, 0) + 1
            else:
                key = "Other IP"
                data[key] = data.setdefault(key, 0) + 1
        return data

    def by_blocklist(self):
        data = {"None":0, "Level 1":0, "Level 2":0,"Both":0}
        for event in self._load_events(eventid="ADD"):
            level_1 = event["ip_details"]["blocklist-level1"]
            level_2 = event["ip_details"]["blocklist-level2"]
            if level_1 and level_2:
                key = "Both"
                data[key] = data.setdefault(key, 0) + 1
            elif level_1:
                key = "Level 1"
                data[key] = data.setdefault(key, 0) + 1
            elif level_2:
                key = "Level 2"
                data[key] = data.setdefault(key, 0) + 1
            else:
                key = "None"
                data[key] = data.setdefault(key, 0) + 1
        return data

    def rule_additions(self):
        data = dict()
        days = (self.end - self.start).days
        for event in self._load_events(eventid="ADD"):
            ip = event["src_ip"]

            if ip in data:
                data[ip].append(event['timestamp'])
            else:
                data[ip] = [event['timestamp']]
        return len(data), len(data)//days

    def rule_deletions(self):
        data = dict()
        days = (self.end - self.start).days
        for event in self._load_events(eventid="DELETE"):
            ip = event["src_ip"]

            if ip in data:
                data[ip].append(event['timestamp'])
            else:
                data[ip] = [event['timestamp']]
        return len(data), len(data)//days


    def by_ports_closed(self):
        data = {"No open ports": 0, "1 open port": 0, "2 open ports": 0, ">= 3 open ports":0}
        for event in self._load_events(eventid="ADD"):
            ports = event["ip_details"]["open-ports"]
            if not ports:
                data["No open ports"]+=1
            elif len(ports) == 1:
                data["1 open port"]+=1
            elif len(ports) == 2:
                data["2 open ports"]+=1
            else:
                data[">= 3 open ports"] += 1
        return data

    def by_ports(self, top=None):
        number_ports = 0
        data = dict()
        for event in self._load_events(eventid="ADD"):
            ports = event["ip_details"]["open-ports"]
            number_ports += len(ports)
            for port in ports:
                try:
                    key = f"{port} ({socket.getservbyport(int(port), 'tcp')})"
                except Exception:
                    key = str(port)
                data[key] = data.setdefault(key, 0) + 1
        print("AVERAGE:")
        print(number_ports/len(list(self._load_events(eventid="ADD"))))

        data = dict(sorted(data.items(), reverse=True, key=lambda item: item[1]))

        if top:
            top_data = dict()
            for key, value in list(data.items())[:top]:
                top_data[key] = value
            top_data["Others"] = 0
            for value in list(data.values())[top:]:
                top_data["Others"] += value
            return top_data

        return data


    def dump_location(self):
        with open("coords.txt", "w") as f:
            for event in self._load_events(eventid="ADD"):
                d = str(event["ip_details"]["geo"]["lat"])+","+str(event["ip_details"]["geo"]["lon"])
                print(d)
                f.write(d+"\n")

    def timestamps_per_ip(self) -> Dict[str, List[datetime]]:
        data = dict()

        events = self._load_events(eventid="ADD")
        for event in events:
            timestamp = parser.parse(event["timestamp"]).replace(tzinfo=None)
            ip = event["src_ip"]

            if ip in data:
                data[ip].append(timestamp)
            else:
                data[ip] = [timestamp]

        #print(data)
        return data