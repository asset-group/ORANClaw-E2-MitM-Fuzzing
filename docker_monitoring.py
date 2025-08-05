import subprocess
import docker
import time
import logging
import threading
import os, sys
import re
from datetime import datetime
from colorama import Fore, Style, init

# Initialize colorama and logging
init(autoreset=True)
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger()

# Configuration
LOGS_DIR = "./asn1/container_logs"
FUZZING_LOGS_DIR = "./asn1/fuzzing_logs"
ERROR_PATTERNS = [
    r"Assertion failed",
    r"Pending event timeout", 
    r"Communication with E2 Node lost",
    r"Connect failed",
    r".c:",
    r"[E2AP]: SCTP_SEND_FAILED"
]

REQUIRED_CONTAINERS = [
    "mongo", "nrf", "scp", "upf", "smf", "pcrf", "amf", "ausf", "udm",
    "pcf", "nssf", "bsf", "udr", "webui", "oai-du-rfsim", "oai-cu-cp",
    "oai-cu-up", "oai-ue-rfsimu-1", "oai-ue-rfsimu-2", "nearRT-RIC",
    "xapp-kmp-monitor"
]

DETAILED_LOG_CONTAINERS = ["oai-du-rfsim", "oai-cu-cp", "oai-cu-up", "nearRT-RIC"
]

CRITICAL_CONTAINERS = ["oai-du-rfsim", "oai-cu-cp", "oai-cu-up", 
                       "nearRT-RIC",]

# Create logs directories
os.makedirs(LOGS_DIR, exist_ok=True)
os.makedirs(FUZZING_LOGS_DIR, exist_ok=True)


def run_command(command):
    """Run shell command with logging."""
    try:
        logger.info(f"{Fore.YELLOW}Executing: {command}{Style.RESET_ALL}")
        subprocess.run(command, shell=True, check=True)
        logger.info(f"{Fore.GREEN}Success: {command}{Style.RESET_ALL}")
    except subprocess.CalledProcessError as e:
        logger.error(f"{Fore.RED}Command failed: {command}, Error: {e}{Style.RESET_ALL}")


def check_for_errors(log_text):
    """Check if any error patterns exist in logs."""
    return any(re.search(pattern, log_text) for pattern in ERROR_PATTERNS)


class DockerMonitor:
    """Synchronized Docker container monitor with MiTM fuzzing."""
    
    def __init__(self):
        self.client = docker.from_env()
        self.lock = threading.Lock()
        self.mitm_process = None
        self.current_session_id = None
        self.log_processes = {}
        
    def start_mitm_session(self):
        """Start MiTM proxy for fuzzing session."""
        try:
            # Kill existing MiTM process
            #subprocess.call(["pkill", "-f", "client_server.py"])

            # Generate session ID
            self.current_session_id = datetime.now().strftime("%Y%m%d_%H%M%S")
            
            # Start MiTM proxy with session logging
            mitm_log_file = f"{FUZZING_LOGS_DIR}/mitm_session_{self.current_session_id}.log"
            
            logger.info(f"{Fore.CYAN}🔍 Starting MiTM fuzzing session: {self.current_session_id}{Style.RESET_ALL}")
            
            with open(mitm_log_file, 'w') as log_file:
                self.mitm_process = subprocess.Popen(
                    ["python3", "client_server.py"],
                    stdout=log_file,
                    stderr=subprocess.STDOUT,
                    cwd="./asn1"
                )
                
            logger.info(f"{Fore.GREEN}✅ MiTM session started{Style.RESET_ALL}")
            return True
            
        except Exception as e:
            logger.error(f"{Fore.RED}❌ Failed to start MiTM session: {e}{Style.RESET_ALL}")
            return False
    
    def stop_mitm_session(self):
        """Stop current MiTM session."""
        try:
            if self.mitm_process:
                logger.info(f"{Fore.YELLOW}🛑 Stopping MiTM session: {self.current_session_id}{Style.RESET_ALL}")
                self.mitm_process.terminate()
                self.mitm_process.wait(timeout=10)
                self.mitm_process = None
                subprocess.call(["pkill", "-f", "client_server.py"])
                logger.info(f"{Fore.GREEN}✅ MiTM session stopped{Style.RESET_ALL}")
                
        except Exception as e:
            logger.error(f"{Fore.RED}❌ Error stopping MiTM session: {e}{Style.RESET_ALL}")
    
    def _execute_recovery(self):
        """Execute recovery by restarting gnb-rfsim profile."""
        with self.lock:
            try:
                logger.warning(f"\n{Fore.MAGENTA}🔧 EXECUTING RECOVERY{Style.RESET_ALL}")
                
                # Stop MiTM session before recovery
                #self.stop_mitm_session()
                
                # Stop log processes during recovery
                self.stop_log_processes()
                
                run_command("docker compose --profile gnb-rfsim down -t0")
                #subprocess.call(["pkill", "-f", "client_server.py"])
                time.sleep(4)
                run_command("docker compose --profile gnb-rfsim up -d")
                time.sleep(3)
                
                # Restart log processes after recovery
                self.start_log_processes()
                
                # Start new MiTM session after recovery
                #self.start_mitm_session()
                
                logger.info(f"{Fore.GREEN}✅ RECOVERY COMPLETED{Style.RESET_ALL}")
                
            except Exception as e:
                logger.error(f"{Fore.RED}❌ RECOVERY FAILED: {e}{Style.RESET_ALL}")
    
    def start_services(self):
        """Start Docker services if needed."""
        running = {c.name for c in self.client.containers.list()}
        missing = [c for c in REQUIRED_CONTAINERS if not any(c in name for name in running)]
        
        if not missing:
            logger.info(f"{Fore.GREEN}✅ All containers running{Style.RESET_ALL}")
            return
            
        logger.info(f"{Fore.CYAN}🚀 Starting services...{Style.RESET_ALL}")
        logger.warning(f"{Fore.YELLOW}⚠️ Missing: {missing}{Style.RESET_ALL}")
        
        run_command("docker compose --profile core up -d")
        time.sleep(3)
        run_command("docker compose --profile gnb-rfsim up -d &")
        time.sleep(3)
        run_command("docker compose --profile xapp up -d")
        time.sleep(3)
    
    def check_logs_for_errors(self, container_name, tail_lines=1000):
        """Check container logs for error patterns using docker logs command."""
        try:
            # Use docker logs command to get recent logs
            result = subprocess.run(
                ["docker", "logs", "--tail", str(tail_lines), container_name],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            logs = result.stdout + result.stderr
            
            if check_for_errors(logs):
                logger.error(f"\n{Fore.RED}❌ ERRORS in {container_name}{Style.RESET_ALL}")
                
                # Save logs with session ID
                session_suffix = f"_{self.current_session_id}" if self.current_session_id else ""
                timestamp = time.strftime("%Y-%m-%d_%H-%M-%S")
                log_file = f"{LOGS_DIR}/{container_name}_error_{timestamp}{session_suffix}.log"
                with open(log_file, 'w') as f:
                    f.write(logs)
                logger.error(f"{Fore.RED}Error logs saved to {log_file}{Style.RESET_ALL}")
                
                # Trigger recovery for critical containers
                if any(name in container_name for name in CRITICAL_CONTAINERS):
                    logger.warning(f"{Fore.MAGENTA}🚨 RECOVERY TRIGGERED{Style.RESET_ALL}")
                    self._execute_recovery()
                
                return True
                
        except subprocess.TimeoutExpired:
            logger.error(f"Timeout checking logs for {container_name}")
        except Exception as e:
            logger.error(f"Error checking logs for {container_name}: {e}")
        
        return False
    
    def start_log_processes(self):
        """Start docker logs processes to write container logs to files in real-time."""
        containers = self.client.containers.list()
        
        for container in containers:
            if any(name in container.name for name in DETAILED_LOG_CONTAINERS):
                try:
                    # Create log file with session ID
                    session_suffix = f"_{self.current_session_id}" if self.current_session_id else ""
                    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                    log_file = f"{LOGS_DIR}/{container.name}_{timestamp}{session_suffix}.log"
                    
                    # Start docker logs process
                    log_handle = open(log_file, 'w')
                    process = subprocess.Popen(
                        ["docker", "logs", "-f", container.name],
                        stdout=log_handle,
                        stderr=subprocess.STDOUT,
                        text=True
                    )
                    
                    self.log_processes[container.name] = {
                        'process': process,
                        'file_handle': log_handle,
                        'log_file': log_file
                    }
                    
                    logger.info(f"{Fore.CYAN}Started log process for {container.name} -> {log_file}{Style.RESET_ALL}")
                    
                except Exception as e:
                    logger.error(f"Failed to start log process for {container.name}: {e}")
        
    def stop_log_processes(self):
        """Stop all docker logs processes."""
        for container_name, log_info in list(self.log_processes.items()):
            try:
                log_info['process'].terminate()
                log_info['file_handle'].close()
                logger.info(f"{Fore.YELLOW}Stopped log process for {container_name}{Style.RESET_ALL}")
            except Exception as e:
                logger.error(f"Error stopping log process for {container_name}: {e}")
        
        self.log_processes.clear()
    
    def restart_log_processes(self):
        """Restart log processes for current containers."""
        self.stop_log_processes()
        time.sleep(1)
        self.start_log_processes()
    
    def restart_xapp_with_sync(self):
        time.sleep(8)
        """Restart xApp container and sync with MiTM."""
        try:
            xapp = next((c for c in self.client.containers.list() if "xapp-kpm-monitor" in c.name), None)
            if xapp:
                logger.info(f"{Fore.MAGENTA}🔄 Restarting xApp and syncing MiTM{Style.RESET_ALL}")
                
                # Stop current MiTM session
                #self.stop_mitm_session()
                #subprocess.call(["pkill", "-f", "client_server.py"])
                # Restart xApp
                xapp.restart()
                time.sleep(3)
                
                # Restart log processes to ensure we capture new logs
                self.restart_log_processes()
                
                # Start new MiTM session
                #self.start_mitm_session()
                
                # Check logs
                self.check_logs_for_errors(xapp.name, tail_lines=50)
            else:
                logger.warning(f"{Fore.YELLOW}⚠️ xApp not found{Style.RESET_ALL}")
        except docker.errors.APIError as e:
            logger.error(f"{Fore.RED}❌ xApp restart failed: {e}{Style.RESET_ALL}")
    
    def monitor(self):
        """Main monitoring loop with synchronized fuzzing."""
        logger.info(f"\n{Fore.CYAN}🔍 Starting synchronized monitor...{Style.RESET_ALL}")
        logger.info(f"{Fore.CYAN}🔧 Auto-recovery: {', '.join(CRITICAL_CONTAINERS)}{Style.RESET_ALL}")
        
        self.start_services()
        self.start_log_processes()
        self.start_mitm_session()

        try:
            counter = 0
            while True:
                containers = self.client.containers.list()

                logger.info(f"\n{Fore.BLUE}{'Container':<40}{'Status':<15}{'Health'}{Style.RESET_ALL}")
                logger.info("-" * 70)

                for container in containers:
                    # Use existing data, no reload
                    status = container.status
                    health = container.attrs.get('State', {}).get('Health', {}).get('Status', 'N/A')

                    color = (
                        Fore.GREEN if health == "healthy"
                        else Fore.RED if health == "unhealthy"
                        else Fore.CYAN if status == "running"
                        else Fore.YELLOW
                    )

                    logger.info(f"{color}{container.name:<40}{status:<15}{health}{Style.RESET_ALL}")

                    if health == "unhealthy":
                        logger.error(f"{Fore.RED}❌ ALERT: {container.name} is {status}/{health}{Style.RESET_ALL}")
                        if any(name in container.name for name in CRITICAL_CONTAINERS):
                            self._execute_recovery()

                logger.info("-" * 70)
                logger.info(f"{Fore.CYAN}MiTM Session: {self.current_session_id or 'None'}{Style.RESET_ALL}")
                logger.info("-" * 70)

                if counter > 0 and counter % 5 == 0:
                    self.restart_xapp_with_sync()
                    
                    for container in containers:
                        if any(name in container.name for name in DETAILED_LOG_CONTAINERS):
                            self.check_logs_for_errors(container.name)

                counter += 1
                time.sleep(2)

        except KeyboardInterrupt:
            logger.info(f"\n{Fore.RED}🛑 Monitoring stopped{Style.RESET_ALL}")
            self.stop_mitm_session()
            self.stop_log_processes()
            sys.exit(0)


if __name__ == "__main__":
    logger.info(f"\n{Fore.GREEN}=== 5G O-RAN Synchronized Monitor Started ==={Style.RESET_ALL}")
    logger.info(f"{Fore.CYAN}Container logs: ./{LOGS_DIR}/{Style.RESET_ALL}")
    logger.info(f"{Fore.CYAN}Fuzzing logs: ./{FUZZING_LOGS_DIR}/{Style.RESET_ALL}")
    
    try:
        monitor = DockerMonitor()
        monitor.monitor()
    except KeyboardInterrupt:
        logger.info(f"\n{Fore.RED}🛑 Script interrupted{Style.RESET_ALL}")
        sys.exit(0)