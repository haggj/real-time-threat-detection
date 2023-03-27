from datetime import datetime
from typing import Dict, List

from dateutil import parser

from logs.abstract_analyzer import AbstractAnalyzer


class HttpsAnalyzer(AbstractAnalyzer):
    log_file = "productive_logs/https_phase2"
    def timestamps_per_ip(self) -> Dict[str, List[datetime]]:
        data = dict()

        with open(self.log_file, "r") as f:
            lines = f.readlines()

        for line in lines:
            ip, timestamp, *_ = line.split("\t")
            timestamp = parser.parse(timestamp)

            if timestamp > self.end or timestamp < self.start or ip in self.whitelisted_ips:
                continue

            if ip in data:
                data[ip].append(timestamp)
            else:
                data[ip] = [timestamp]

        return data
