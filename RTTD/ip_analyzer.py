import requests
import os
from pprint import pprint
import nmap3


class IpAnalyzer:

    def __init__ (self):
        """
        Initialize all data needed for the checks.
        """
        self.checks = [
            self.check_blocklist_ipsets,
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
        return "blocklist-ipsets", True
    
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