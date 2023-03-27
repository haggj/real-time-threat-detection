import json
import os
from datetime import timedelta, datetime
from typing import Dict, List

from dateutil import parser

from logs.abstract_analyzer import AbstractAnalyzer


class SSHAnalyzer(AbstractAnalyzer):
    log_folder = "productive_logs/cowrie"

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
