import ast
import re

class ASTParser:
    def __init__(self):
        pass

    def parse_file(self, file_path):
        """Parse a file and return behavior tokens."""
        content = ""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
        except:
            return []

        # Convert simple Path to string for suffix check
        suffix = str(file_path).lower()
        if suffix.endswith('.py'):
            return self.parse_python(content)
        elif suffix.endswith('.js'):
            return self.parse_js(content)
        return []

    def parse_python(self, code):
        """Parse Python source into a simplified list of nodes."""
        try:
            tree = ast.parse(code)
            tokens = []
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        tokens.append(f"IMPORT_{alias.name.upper()}")
                elif isinstance(node, ast.ImportFrom):
                    mod_name = node.module.upper() if node.module else "UNKNOWN" # type: ignore
                    tokens.append(f"IMPORT_{mod_name}")
                elif isinstance(node, ast.Call):
                    func_name = ""
                    if isinstance(node.func, ast.Name):
                        func_name = node.func.id # type: ignore
                    elif isinstance(node.func, ast.Attribute):
                        attr_val = "UNKNOWN"
                        if hasattr(node.func, 'value'):
                            node_val = node.func.value # type: ignore
                            if hasattr(node_val, 'id'):
                                attr_val = getattr(node_val, 'id')
                            elif hasattr(node_val, 'attr'):
                                attr_val = getattr(node_val, 'attr')
                            elif isinstance(node_val, ast.Name):
                                attr_val = node_val.id
                        
                        func_name = f"{attr_val}.{node.func.attr}" # type: ignore
                    
                    if func_name:
                        tokens.append(f"CALL_{func_name.upper()}")
                
                # Support different python versions for string extraction
                if hasattr(ast, 'Constant') and isinstance(node, ast.Constant) and isinstance(node.value, str):
                    if len(node.value) > 3:
                        tokens.append(f"STR_{str(node.value)[:100]}") # type: ignore
                elif isinstance(node, ast.Str):
                    if hasattr(node, 's') and len(node.s) > 3:
                        tokens.append(f"STR_{str(node.s)[:100]}")  # type: ignore
            return tokens
        except Exception as e:
            return [f"ERROR_PY_PARSE: {str(e)[:50]}"] # type: ignore

    def parse_js(self, code):
        """Robust token-based JS parser for security analysis (no external dependencies)."""
        tokens = []
        
        # 1. Capture imports/requires
        import_patterns = [
            r"(?:import|require)\s*\(?\s*['\"]([^'\"]+)['\"]\s*\)?",
            r"import\s+.*\s+from\s+['\"]([^'\"]+)['\"]"
        ]
        for pattern in import_patterns:
            matches = re.findall(pattern, code)
            for imp in matches:
                tokens.append(f"IMPORT_JS_{imp.upper()}")

        # 2. Capture function calls (filtered for security relevance)
        call_patterns = [
            r"([a-zA-Z0-9_$]+(?:\.[a-zA-Z0-9_$]+)*)\s*\(",
        ]
        sensitive_keywords = ["EXEC", "SYSTEM", "EVAL", "PROCESS", "FS.", "HTTP", "FETCH", "SOCKET", "CHILD_PROCESS", "SPAWN", "UNLINK", "WRITEFILE", "ENV", "BASE64"]
        for pattern in call_patterns:
            matches = re.findall(pattern, code)
            for call in matches:
                upper_call = call.upper()
                if any(k in upper_call for k in sensitive_keywords):
                    tokens.append(f"CALL_{upper_call}")

        # 3. Capture suspicious strings
        string_patterns = [
            r"['\"](https?://[^'\"]{5,200})['\"]",
            r"['\"](/[a-zA-Z0-9_/.-]{10,200})['\"]",
            r"['\"]([a-zA-Z0-9+/=]{20,})['\"]"
        ]
        for pattern in string_patterns:
            matches = re.findall(pattern, code)
            for s in matches:
                tokens.append(f"STR_{s[:100]}")

        # 4. Special JS properties
        if "process.env" in code:
            tokens.append("CALL_PROCESS.ENV")

        return tokens
