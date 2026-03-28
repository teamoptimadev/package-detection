
import os
import sys
import json
import subprocess
import socket
from pathlib import Path

# Tracking intercepted events
LOGS = []

def log_event(category, details):
    LOGS.append({
        "category": category,
        "details": details
    })

# --- Monkey Patching ---

# 1. Patch OS/Subprocess (Shell Execution)
_original_system = os.system
def patched_system(command):
    category = "SHELL_EXECUTION"
    if any(cmd in command for cmd in ["lspci", "lsusb", "dmidecode"]):
        category = "ENVIRONMENT_PROBING"
    log_event(category, {"command": command, "method": "os.system"})
    return 0 # Success but do nothing real

os.system = patched_system

_original_run = subprocess.run
def patched_run(args, **kwargs):
    cmd = args if isinstance(args, str) else " ".join(map(str, args))
    category = "SHELL_EXECUTION"
    if any(c in cmd for c in ["lspci", "lsusb", "dmidecode"]):
        category = "ENVIRONMENT_PROBING"
    log_event(category, {"command": cmd, "method": "subprocess.run"})
    class MockResult:
        returncode = 0
        stdout = b""
        stderr = b""
    return MockResult()

subprocess.run = patched_run # type: ignore

# 2. Patch Sockets (Network Egress)
_original_connect = socket.socket.connect
def patched_connect(self, address):
    log_event("NETWORK_CONNECTION", {"host": address[0], "port": address[1]})
    raise ConnectionRefusedError(f"Sandboxed: Connection to {address} blocked.")

socket.socket.connect = patched_connect

# 3. Patch Inspect (Introspection Detection)
try:
    import inspect
    _original_getsource = inspect.getsource
    def patched_getsource(obj):
        log_event("INTROSPECTION_DETECTION", {"object": str(obj), "method": "inspect.getsource"})
        return _original_getsource(obj)
    inspect.getsource = patched_getsource # type: ignore
    
    _original_getfile = inspect.getfile
    def patched_getfile(obj):
        log_event("INTROSPECTION_DETECTION", {"object": str(obj), "method": "inspect.getfile"})
        return _original_getfile(obj)
    inspect.getfile = patched_getfile # type: ignore
except ImportError:
    pass

# --- Execution ---

import runpy

def run_analysis(package_path):
    sys.path.insert(0, str(package_path))
    
    scripts_to_run = list(package_path.glob("*.py"))
    
    # Prioritize certain scripts
    priority = ["setup.py", "malware.py", "main.py", "index.py"]
    scripts_to_run.sort(key=lambda x: priority.index(x.name) if x.name in priority else 999)

    for script in scripts_to_run:
        try:
            # Using run_path to execute the script as __main__
            # This triggers code inside if __name__ == "__main__":
            runpy.run_path(str(script), run_name="__main__")
        except Exception as e:
            log_event("RUNTIME_ERROR", {"script": script.name, "message": str(e)})

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(json.dumps({"error": "No package path provided"}))
        sys.exit(1)
        
    pkg_path = Path(sys.argv[1])
    run_analysis(pkg_path)
    
    # Output logs to stdout as JSON for the host to parse
    print("---SANDBOX_RESULTS_START---")
    print(json.dumps(LOGS))
    print("---SANDBOX_RESULTS_END---")
