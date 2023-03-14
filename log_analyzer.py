from datetime import datetime
from typing import List, Tuple, Dict

from dateutil import parser


class AbstractAnalyzer:
    def __init__(self):
        self.start = datetime.strptime('12-03-2023', '%d-%m-%Y')
        self.end = datetime.strptime('13-03-2023', '%d-%m-%Y')

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
    def timestamps_per_ip(self) -> Dict[str, List[datetime]]:
        data = dict()

        with open("example_logs/https_logs", "r") as f:
            lines = f.readlines()

        for line in lines:
            ip, timestamp, *_ = line.split("\t")
            timestamp = parser.parse(timestamp)

            if timestamp > self.end or timestamp < self.start:
                continue

            if ip in data:
                data[ip].append(timestamp)
            else:
                data[ip] = [timestamp]

        return data


a = HttpsAnalyzer()
print(a.timestamps_per_ip())
print(a.total_connections())
print(a.connections_per_day())
print(a.unique_ips())
print(a.ips_connected_multiple())

