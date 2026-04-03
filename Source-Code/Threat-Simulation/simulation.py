import subprocess

class ThreatSimulator:
    def test_weak_credentials(self, target_ip, username="admin"):
        # Uses a small built-in wordlist for "safe" testing
        pass_list = "/usr/share/wordlists/metasploit/unix_passwords.txt"
        cmd = ["hydra", "-l", username, "-P", pass_list, f"ssh://{target_ip}", "-t", "4"]
        
        try:
            result = subprocess.check_output(cmd, stderr=subprocess.STDOUT).decode()
            if "login:" in result:
                return "CRITICAL: Weak credentials found!"
            return "No weak credentials detected."
        except subprocess.CalledProcessError as e:
            return "Simulation scan complete (no hits)."

