import psutil

class ProcessReviewer:
    def get_running_processes(self):
        processes = []
        for proc in psutil.process_iter(['pid', 'name', 'username']):
            processes.append(proc.info)
        return processes # Pass this list to your GUI table
