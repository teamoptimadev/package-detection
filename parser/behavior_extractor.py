import re

class BehaviorExtractor:
    def __init__(self):
        # Mappings of calls to common malicious behaviors
        self.mapping = {
            # Shell/System
            r"(OS\.SYSTEM|SUBPROCESS|SH\.|CHILD_PROCESS\.EXEC|EXEC|EVAL)": "SHELL_EXECUTION",
            # Network
            r"(REQUESTS\.GET|REQUESTS\.POST|AXIOS|FETCH|HTTP\.GET|URLLIB|BOTO3)": "NETWORK_REQUEST",
            # File System
            r"(OS\.REMOVE|FS\.UNLINK|SHUTIL\.RMTREE|OPEN\.|FS\.WRITE)": "FILE_ACCESS",
            # Exfiltration/Environment
            r"(ENVIRON|PROCESS\.ENV|GETENV)": "ENV_VARIABLE_ACCESS",
            # Persistence / Startup
            r"(REGISTRY|CRONTAB|SYSTEMD)": "PERSISTENCE_MECHANISM",
            # Obfuscation
            r"(BASE64|B64DECODE|ATOB|BUFFER\.FROM)": "DATA_ENCODING"
        }

    def extract(self, tokens):
        """Process tokens into a clean list of detected behaviors."""
        behaviors = []
        
        # Check calls against mapping
        for token in tokens:
            if "CALL_" in token:
                func_name = token.replace("CALL_", "")
                for pattern, category in self.mapping.items():
                    if re.search(pattern, func_name):
                        behaviors.append(category)
            
            if "IMPORT_" in token:
                imp_name = token.replace("IMPORT_", "")
                if any(x in imp_name for x in ["OS", "SUBPROCESS", "SOCKET", "REQUESTS", "PICKLE"]):
                    behaviors.append(f"IMPORT_SENSITIVE_{imp_name}")

            if "STR_" in token:
                val = token.replace("STR_", "").lower()
                if "http" in val:
                    behaviors.append("URL_FOUND")
                if "/etc/passwd" in val or ".ssh" in val or "token" in val:
                    behaviors.append("SENSITIVE_STRING_FOUND")
        
        # Return unique behaviors
        return sorted(list(set(behaviors)))

    def to_natural_language(self, behaviors):
        """Convert a list of behaviors into a description for RAG."""
        if not behaviors:
            return "No suspicious behaviors detected."
            
        desc_map = {
            "SHELL_EXECUTION": "executes shell or system commands",
            "NETWORK_REQUEST": "performs network requests to remote servers",
            "FILE_ACCESS": "accesses or modifies local file system",
            "ENV_VARIABLE_ACCESS": "reads environment variables containing sensitive info",
            "DATA_ENCODING": "uses encoding like base64 to obfuscate data",
            "URL_FOUND": "contains hardcoded URLs",
            "SENSITIVE_STRING_FOUND": "accesses sensitive file paths or credentials"
        }
        
        phrases = []
        for b in behaviors:
            if b in desc_map:
                phrases.append(desc_map[b]) # type: ignore
            elif "IMPORT_SENSITIVE" in b:
                phrases.append(f"imports sensitive module {b.split('_')[-1]}") # type: ignores
                
        return "this code " + " and ".join(phrases)
