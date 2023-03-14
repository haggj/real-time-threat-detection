import json
import os
from datetime import datetime, timedelta
from typing import List, Tuple, Dict

from dateutil import parser


class AbstractAnalyzer:
    def __init__(self):
        self.start = datetime.strptime('10-03-2023', '%d-%m-%Y')
        self.end = datetime.strptime('11-03-2023', '%d-%m-%Y')
        self.whitelisted_ips = ['130.208.240.12', '85.220.40.135', '129.187.205.52', '129.187.207.88']

    def total_connections(self) -> int:
        """
        Total connections in time frame.
        """
        sum = 0
        for ip, connections in self.timestamps_per_ip().items():
            sum += len(connections)
        return sum
    def connections_per_day(self) -> float:
        """
        Average connections per day in time frame.
        """
        days = (self.end - self.start).days
        return self.total_connections()//days
    def unique_ips(self) -> int:
        """
        Number of unique IPs which connected during time frame.
        """
        return len(self.timestamps_per_ip())

    def ips_connected_once(self) -> int:
        """
        Number of IPs which connected only once during time frame.
        """
        return len([ip for ip, connections in self.timestamps_per_ip().items() if len(connections) == 1])

    def ips_connected_multiple(self) -> List[Tuple[str, List[datetime]]]:
        """
        Number of IPs which connected multiple times during time frame.
        """
        return self.unique_ips() - self.ips_connected_once()

    def timestamps_per_ip(self) -> Dict[str, List[datetime]]:
        """
        Returns a dictionary. Keys are the unique IPs. Values are lists containing the timestamps of
        when this IP connected to the service.
        {
            "1.2.3.4": [
                datetime.strptime('08-03-2011', '%d-%m-%Y'),
                datetime.strptime('07-03-2011', '%d-%m-%Y'),
                datetime.strptime('06-03-2011', '%d-%m-%Y')
            ],
            "1.2.3.5": [
                datetime.strptime('08-03-2011', '%d-%m-%Y'),
                datetime.strptime('06-03-2011', '%d-%m-%Y')
            ],
            "1.2.3.6": [
                datetime.strptime('08-03-2011', '%d-%m-%Y'),
            ]
        }
        """
        raise NotImplementedError()


class HttpsAnalyzer(AbstractAnalyzer):
    log_file = "example_logs/https_logs"
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


class HttpAnalyzer(HttpsAnalyzer):
    log_file = "example_logs/http_logs"


class SSHAnalyzer(AbstractAnalyzer):
    log_folder = "example_logs/cowrie"

    def _log_files(self):
        """
        Returns all log files for the defined time frame.
        """
        log_files = []
        delta = self.end - self.start
        for i in range(delta.days):
            day = self.start + timedelta(days=i)
            formatted_day = day.strftime("%Y-%m-%d")
            file = f"{self.log_folder}/cowrie.json.{formatted_day}"
            if os.path.isfile(file):
                log_files.append(file)
        return log_files

    def _load_by_eventid(self, eventid):
        """
        Loads all events of the specified eventid during time frame.
        """
        for log_file in self._log_files():
            with open(log_file, "r") as f:
                lines = f.readlines()

            for line in lines:
                event = json.loads(line)
                ip = event["src_ip"]
                timestamp = parser.parse(event["timestamp"]).replace(tzinfo=None)

                if event["eventid"] != eventid:
                    continue

                if ip not in self.whitelisted_ips and self.start <= timestamp <= self.end:
                    yield event
    def successful_logins(self):
        """
        Get the successful logins to the honeypot.
        Returns a list of tuples. Each tuple contains the probed username/password combination.
        """
        events = self._load_by_eventid("cowrie.login.success")
        for event in events:
            yield event["username"], event["password"]

    def failed_logins(self):
        """
        Get the failed logins to the honeypot.
        Returns a list of tuples. Each tuple contains the probed username/password combination.
        """
        events = self._load_by_eventid("cowrie.login.failed")
        for event in events:
            yield event["username"], event["password"]

    def downloads(self):
        """
        Get the downloads attempts of attackers.
        Returns a list of tuples. Each tuple contains the URL and the SHASUM of the approached file.
        """
        events = self._load_by_eventid("cowrie.session.file_download")
        for event in events:
            yield event["url"], event["shasum"]

    def commands_per_session(self):
        """
        Get the executed commands in the faked shell.
        Returns a dict. Keys are the session ids. Values are the executed commands in this session.
        """
        events = self._load_by_eventid("cowrie.command.input")
        sessions = dict()
        print(sessions)
        for event in events:
            sess_id = event["session"]
            if sess_id in sessions:
                sessions[sess_id].append(event["input"])
                print(sessions)
            else:
                sessions[sess_id] = [event["input"]]
                print(sessions)

        return sessions


    def timestamps_per_ip(self) -> Dict[str, List[datetime]]:
        data = dict()

        events = self._load_by_eventid("cowrie.session.connect")
        for event in events:
            timestamp = parser.parse(event["timestamp"]).replace(tzinfo=None)
            ip = event["src_ip"]

            if ip in data:
                data[ip].append(timestamp)
            else:
                data[ip] = [timestamp]

        return data



for service in [SSHAnalyzer(), HttpsAnalyzer(), HttpAnalyzer()]:

    print(service.__class__)
    print("Total connections:\t", service.total_connections())
    print("Connections/day:\t", service.connections_per_day())
    print("Unique IPs:\t\t", service.unique_ips())
    print("Returning IPs:\t\t", service.ips_connected_multiple())
    print()

