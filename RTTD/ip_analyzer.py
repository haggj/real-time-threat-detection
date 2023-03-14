from datetime import datetime, timedelta

import requests
import os
from pprint import pprint
import nmap3
import ipaddress


class IpAnalyzer:

    def __init__ (self):
        """
        Initialize all data needed for the checks.
        """
        level1_url = 'https://iplists.firehol.org/files/firehol_level1.netset'
        level2_url = 'https://iplists.firehol.org/files/firehol_level2.netset'
        tor_exit_url = 'https://www.dan.me.uk/torlist/?exit'

        self.ipsets_level1 = self._ensure_url_content(url=level1_url, cached_file="./level_1")
        self.ipsets_level2 = self._ensure_url_content(url=level2_url, cached_file="./level_2")
        self.tor_exit_nodes = self._ensure_url_content(url=tor_exit_url, cached_file='./cached_tor_exit')

        self.checks = [
            self.check_blocklist_level1,
            self.check_blocklist_level2,
            self.check_tor_exit_node,
            self.check_geo_location,
            self.check_residential,
            self.check_open_ports
        ]

    def _ensure_url_content(self, url, cached_file, cache_time=timedelta(hours=1)):
        """
        Returns the content of the requested url. The content is cached for the specified cache_time
        in the specified cache_file.
        """

        fetch_content = False

        # Check if file should be fetched
        if os.path.exists(cached_file):
            modified = datetime.fromtimestamp(os.path.getmtime(cached_file))
            last_hour = datetime.now() - cache_time
            if modified < last_hour:
                fetch_content = True
        else:
            fetch_content = True

        # Either load file from cache or perform a new request
        if fetch_content:
            data = requests.get(url).content.decode()
            with open(cached_file, 'w') as file:
                file.write(data)
        else:
            with open(cached_file, 'r') as content_file:
                data = content_file.read()
        return data

    def run(self, ip: str):
        """
        Running all checks
        """
        result = dict()
        
        for check in self.checks:
            key, val = check(ip=ip)
            result[key] = val
        
        return result

    def _check_blocklist(self, blocklist, raw_ip: str):
        """
        Check if IP is part of a blocklist.
        """
        found = False
        lookup_ip = ipaddress.ip_address(raw_ip)
        for ip_range in blocklist.splitlines():
            try:
                if lookup_ip in ipaddress.ip_network(ip_range):
                    found = True
                    break
            except ValueError:
                pass
        return found

    def check_blocklist_level1(self, ip: str):
        return "blocklist-level1", self._check_blocklist(self.ipsets_level1, ip)

    def check_blocklist_level2(self, ip: str):
        return "blocklist-level2", self._check_blocklist(self.ipsets_level2, ip)

    def check_tor_exit_node(self, ip: str):
        found = False
        for exit_raw in self.tor_exit_nodes.splitlines():
            exit_ip = ipaddress.ip_address(exit_raw)
            if exit_ip.version == "6":
                continue
            if exit_ip == ipaddress.ip_address(ip):
                found = True
        return "tor-exit-node", found
    
    def check_residential(self, ip: str):
        """
        Use iphub.com to check if IP is proxy/vpn or residential IP.
        """
        api_key = os.environ.get('IPHUB_KEY', None)
        if not api_key:
            raise Exception("Missing environment variable: IPHUB_KEY")
        res = requests.get(f"http://v2.api.iphub.info/ip/{ip}", headers={"X-Key": api_key})
        residential = res.json().get("block") == 0
        return "residential", residential
    
    def check_geo_location(self, ip: str):
        """
        Use ip-api.com to geocode the IP address.
        """
        res = requests.get(f"http://ip-api.com/json/{ip}")
        data = res.json()
        geo = {
            'country': data["country"],
            'city': data.get("city", None),
            'lat': data["lat"],
            'lon': data["lon"],
        }
        return "geo", geo

    def check_open_ports(self, ip: str):
        """
        Use nmap to scan for open ports.
        """
        nmap = nmap3.Nmap()
        results = nmap.scan_top_ports(ip, 30)
        open_ports = [port["portid"] for port in results[ip]["ports"] if port["state"]=="open"]
        return "open-ports", open_ports
    
    
if __name__=="__main__":
    analyzer = IpAnalyzer()
    start = datetime.now()
    res = analyzer.run("20.241.236.196")
    duration = datetime.now() - start
    pprint(res)
    print(duration)