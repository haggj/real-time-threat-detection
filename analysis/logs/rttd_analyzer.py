import json
from datetime import datetime
from typing import Dict, List

from dateutil import parser

from logs.abstract_analyzer import AbstractAnalyzer


class RTTDAnalyzer(AbstractAnalyzer):
    log_file = "example_logs/rttd_logs.txt"
    def _load_events(self, eventid=None):
        with open(self.log_file, "r") as f:
            lines = f.readlines()

        for line in lines:
            event = json.loads(line)
            ip = event["src_ip"]
            timestamp = parser.parse(event["timestamp"]).replace(tzinfo=None)

            if eventid and event["event"] != eventid:
                continue

            if ip not in self.whitelisted_ips and self.start <= timestamp <= self.end:
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
                key = "Service provider IPs"
                data[key] = data.setdefault(key, 0) + 1
        return data

    def timestamps_per_ip(self) -> Dict[str, List[datetime]]:
        data = dict()

        events = self._load_events()
        for event in events:
            timestamp = parser.parse(event["timestamp"]).replace(tzinfo=None)
            ip = event["src_ip"]

            if ip in data:
                data[ip].append(timestamp)
            else:
                data[ip] = [timestamp]

        return data
