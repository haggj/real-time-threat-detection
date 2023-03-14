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
        # Load Level 1 & Level 2 ipsets from firehol
        # TODO: Tor node list is only once every 30min availabe! Load List to file
        level1_url = 'https://iplists.firehol.org/files/firehol_level1.netset'
        level2_url = 'https://iplists.firehol.org/files/firehol_level2.netset'
        tor_nodes_url = 'https://www.dan.me.uk/torlist/?exit'
        self.ipsets_level1 = requests.get(level1_url).content.decode()
        self.ipsets_level2 = requests.get(level2_url).content.decode()
        self.tor_exit_nodes = requests.get(tor_nodes_url).content.decode()

        self.checks = [
            self.check_blocklist_ipsets,
            self.check_tor_exit_node,
            self.check_geo_location,
            self.check_residential,
            self.check_open_ports
        ]

    def run(self, ip: str):
        """
        Running all checks
        """
        result = dict()
        
        for check in self.checks:
            key, val = check(ip=ip)
            result[key] = val
        
        return result
    
    def check_blocklist_ipsets(self, ip: str):
        check_level1 = False
        line_counter = 0
        for ip_range in self.ipsets_level1.splitlines():
            # skip first 33 lines of Overhead in file
            line_counter = line_counter + 1
            if line_counter > 33:
                if ipaddress.ip_address(ip) in ipaddress.ip_network(ip_range):
                    check_level1 = True
                    break

        check_level2 = False
        line_counter = 0
        for ip_range in self.ipsets_level2.splitlines():
            # skip first 31 lines of Overhead in file
            line_counter = line_counter + 1
            if line_counter > 31:
                if ipaddress.ip_address(ip) in ipaddress.ip_network(ip_range):
                    check_level2 = True
                    break

        return "blocklist-ipsets", (check_level1 or check_level2)

    def check_tor_exit_node(self, ip: str):
        # TODO: Tor node list is only once every 30min availabe! Load List to file
        #check = False
        #for ip_range in self.tor_exit_nodes.splitlines():
        #    if ipaddress.ip_address(ip) in ipaddress.ip_network(ip_range):
        #        check = True
        #        break

        #return "tor-exit-node", check
        return "tor-exit-node", True
    
    def check_residential(self, ip: str):
        """
        Use iphub.com to check if IP is proxy/vpn or residential IP.
        """
        api_key = os.environ.get('IPHUB_KEY', None)
        if not api_key:
            raise Exception("Missing environment variable: IPHUB_KEY")
        print(api_key)
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
        results = nmap.scan_top_ports(ip, 20)
        open_ports = [port["portid"] for port in results[ip]["ports"] if port["state"]=="open"]
        return "open-ports", open_ports
    
    
if __name__=="__main__":
    analyzer = IpAnalyzer()
    res = analyzer.run("20.241.236.196")
    print(res)