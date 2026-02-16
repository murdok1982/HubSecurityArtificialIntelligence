import time
import psutil
import logging
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from edr.config import config
from edr.telemetry import TelemetryClient
from edr.scanner import EDRScanner

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger("HispanShieldEDR")

class FileMonitorHandler(FileSystemEventHandler):
    def __init__(self, scanner, telemetry):
        self.scanner = scanner
        self.telemetry = telemetry

    def on_created(self, event):
        if not event.is_directory:
            self._handle_change(event.src_path, "created")

    def on_modified(self, event):
        if not event.is_directory:
            self._handle_change(event.src_path, "modified")

    def _handle_change(self, file_path, action):
        logger.info(f"File {action}: {file_path}")
        # Skip small files or specific extensions if needed
        scan_result = self.scanner.scan_file(file_path)
        if scan_result["status"] == "malicious":
            logger.warning(f"THREAT DETECTED in {file_path}: {scan_result['detections']}")
            self.telemetry.send_event("file_threat", scan_result)
        else:
            # Low priority telemetry for auditing
            pass

class EDRAgent:
    def __init__(self):
        self.telemetry = TelemetryClient(config.BACKEND_URL, config.API_KEY, config.DEVICE_ID)
        self.scanner = EDRScanner(config.RULES_PATH)
        self.known_pids = set()

    def run(self):
        logger.info("HispanShield EDR Agent Starting...")
        
        # 1. Start File Monitor
        observer = Observer()
        handler = FileMonitorHandler(self.scanner, self.telemetry)
        observer.schedule(handler, config.WATCH_PATH, recursive=False) # Watch root but not recursive for dev safety
        observer.start()
        
        logger.info(f"Monitoring file system: {config.WATCH_PATH}")

        try:
            while True:
                # 2. Process Monitoring
                self._monitor_processes()
                
                # 3. Sync Intelligence (Periodic)
                # For MVP, just sync once or every N loops
                
                time.sleep(config.PROCESS_LOG_INTERVAL)
        except KeyboardInterrupt:
            observer.stop()
        observer.join()

    def _monitor_processes(self):
        current_pids = set(psutil.pids())
        new_pids = current_pids - self.known_pids
        
        for pid in new_pids:
            try:
                proc = psutil.Process(pid)
                proc_info = proc.as_dict(attrs=['pid', 'name', 'exe', 'cmdline', 'username'])
                
                if proc_info['exe']:
                    # Scan the executable
                    scan_result = self.scanner.scan_file(proc_info['exe'])
                    if scan_result["status"] == "malicious":
                        logger.warning(f"MALICIOUS PROCESS DETECTED: {proc_info['name']} (PID: {pid})")
                        self.telemetry.send_event("process_threat", {
                            "process": proc_info,
                            "detection": scan_result
                        })
                    else:
                        # Log new process for audit
                        # self.telemetry.send_event("process_start", proc_info)
                        pass
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        
        self.known_pids = current_pids

if __name__ == "__main__":
    agent = EDRAgent()
    agent.run()
