from datetime import datetime, timedelta
from typing import Dict, List
import re

from dateutil import parser

from logs.abstract_analyzer import AbstractAnalyzer


class HttpsAnalyzer(AbstractAnalyzer):
    log_file = "productive_logs/https_phase2"

    """
    HTTPS connections could not be logged due to UnicodeEncoding errors. Each HTTPs connection threw
    an exception into nohoup.log. This data only contains the IP but not a timestamp.
    The file contains data for 19 days:
        - Birth: 03-09-2023 14:49
        - Last Modify: 03-28-2023 13:44
    Assuming that there were the same amount of incoming connections per day, we compute the average 
    number of incoming HTTPs connections per day. This allows us to assign incoming connections to
    the days in which the log was created.
    Based on the selected time frame, we then return the assign the ips to days.
    """
    nohup = "productive_logs/https_nohup"

    def https_connections(self):

        # Parse nohup exceptions to list
        data = list()
        with open(self.nohup, "r") as f:
            found_error = False
            lines = f.readlines()
            for idx, line in enumerate(reversed(lines)):
                if found_error:
                    if line.startswith("INFO:"):
                        # IP causing error found, print and search for next error
                        result = re.search(r"root:\('(.*)', ", line)
                        ip = result.group(1)
                        data.append(ip)
                        found_error = False
                if line.startswith("UnicodeDecodeError"):
                    found_error = True

        # Bucket exceptions into days. Assumption: Connections ar equally distributed over time.
        nohup_start = datetime.strptime('09-03-2023', '%d-%m-%Y')
        nohup_end = datetime.strptime('28-03-2023', '%d-%m-%Y')
        delta = nohup_end - nohup_start
        avg_per_day = len(data)//delta.days

        connections_per_day = dict()
        for i in range(delta.days):
            day = nohup_start + timedelta(days=i)
            connections_per_day[day] = data[i*avg_per_day:(i+1)*avg_per_day]

        # Compute the connections based on the specified time frame
        relevant_connections = dict()
        delta = self.end - self.start
        for i in range(delta.days):
            day = self.start + timedelta(days=i)
            if day in connections_per_day:
                for ip in connections_per_day[day]:
                    # TODO assign better time than 00:00 time to connections
                    relevant_connections.setdefault(ip, []).append(day)

        return relevant_connections


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


        if self.__class__.__name__ == "HttpsAnalyzer":
            # Add HTTPs connections
            data.update(self.https_connections())
        return data
