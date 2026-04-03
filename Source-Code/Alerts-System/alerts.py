class AlertSystem:
    def __init__(self):
        self.rules = {
            "critical_ports": [21, 22, 23, 80],
            "suspicious_apps": ["nc", "ncat", "wireshark"]
        }

    def check_severity(self, port):
        if port in self.rules["critical_ports"]:
            return "HIGH"
        return "LOW"
