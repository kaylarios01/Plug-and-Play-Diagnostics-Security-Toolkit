import nmap
import json

class NetworkScanner:
    def __init__(self):
        self.nm = nmap.PortScanner()

    def scan_target(self, target_ip):
        # -sV: Service version detection, -O: OS detection
        self.nm.scan(target_ip, arguments='-sV -O')
        scan_data = []
        
        for host in self.nm.all_hosts():
            host_info = {
                "host": host,
                "status": self.nm[host].state(),
                "os": self.nm[host].get('osmatch', [{}])[0].get('name', 'Unknown'),
                "protocols": []
            }
            for proto in self.nm[host].all_protocols():
                ports = self.nm[host][proto].keys()
                for port in ports:
                    port_info = {
                        "port": port,
                        "name": self.nm[host][proto][port]['name'],
                        "product": self.nm[host][proto][port]['product'],
                        "version": self.nm[host][proto][port]['version']
                    }
                    host_info["protocols"].append(port_info)
            scan_data.append(host_info)
        return scan_data

# Test logic
if __name__ == "__main__":
    scanner = NetworkScanner()
    print(json.dumps(scanner.scan_target('127.0.0.1'), indent=4))
