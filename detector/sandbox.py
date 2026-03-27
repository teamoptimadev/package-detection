import subprocess
import os
import json
import tempfile
from pathlib import Path
import shutil

class SandboxManager:
    def __init__(self, timeout=20):
        self.timeout = timeout
        self.image = "python:3.11-slim" # Minimal, fast image
        
        # Mac Specific: Ensure Docker socket is correctly identified
        if os.name == "posix" and "darwin" in os.sys.platform:
            default_socket = f"/Users/{os.getlogin()}/.docker/run/docker.sock"
            if os.path.exists(default_socket):
                os.environ["DOCKER_HOST"] = f"unix://{default_socket}"
        
    def run_dynamic_analysis(self, package_path):
        """Execute a package in a Docker sandbox and track its behavior."""
        try:
            # 1. Prepare Workspace
            # We copy our wrapper script and the package content into a temporary 
            # directory to mount it as a single volume.
            with tempfile.TemporaryDirectory() as temp_dir:
                temp_path = Path(temp_dir)
                
                # Copy the wrapper
                wrapper_src = Path(__file__).parent.parent / "utils" / "sandbox_wrapper.py"
                shutil.copy(wrapper_src, temp_path / "sandbox_wrapper.py")
                
                # Copy the package content
                pkg_dir = temp_path / "package"
                shutil.copytree(package_path, pkg_dir, ignore=shutil.ignore_patterns('__pycache__', '*.pyc'))
                
                # 2. Run Container
                cmd = [
                    "docker", "run", "--rm",
                    "-v", f"{temp_path}:/analysis",
                    "-w", "/analysis",
                    "--network", "none", # Total network isolation
                    "--memory", "256m", # Memory limit
                    "--cpus", "0.5",     # CPU limit
                    self.image,
                    "python3", "sandbox_wrapper.py", "package"
                ]
                
                # Execute with timeout
                result = subprocess.run(
                    cmd, 
                    capture_output=True, 
                    text=True, 
                    timeout=self.timeout
                )
                
                # 3. Parse Output
                return self._parse_output(result.stdout)
                
        except subprocess.TimeoutExpired:
            return [{"category": "SYSTEM", "details": "Sandbox timed out during check."}]
        except Exception as e:
            return [{"category": "ERROR", "details": f"Sandbox failed: {str(e)}"}]

    def _parse_output(self, output):
        """Extract the JSON log between the delimiters."""
        try:
            start_tag = "---SANDBOX_RESULTS_START---"
            end_tag = "---SANDBOX_RESULTS_END---"
            
            if start_tag in output and end_tag in output:
                json_str = output.split(start_tag)[1].split(end_tag)[0].strip()
                return json.loads(json_str)
            return []
        except:
            return []
