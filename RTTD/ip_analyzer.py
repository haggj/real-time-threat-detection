class IpAnalyzer:

    def __init__ (self):
        """
        Initialize all data needed for the checks.
        """
        self.checks = [
            self.check_blocklist_ipsets
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
    
if __name__=="__main__":
    analyzer = IpAnalyzer()
    res = analyzer.run("130.208.240.12")
    print(res)