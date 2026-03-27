import textwrap

class LLMAnalyzer:
    def __init__(self):
        # Weights for different behaviors to calculate risk score
        self.risk_weights = {
            "SHELL_EXECUTION": 45,
            "ENV_VARIABLE_ACCESS": 35,
            "NETWORK_REQUEST": 20,
            "FILE_ACCESS": 15,
            "SENSITIVE_STRING_FOUND": 30,
            "DATA_ENCODING": 10,
            "URL_FOUND": 5
        }

    def analyze(self, behaviors, rag_results, dynamic_results=None):
        """Perform simulated LLM analysis of the package behaviors and RAG matches."""
        
        # 1. Calculate Base Risk Score
        score = 0
        matched_indicators = []
        
        # Process static behaviors
        for b in behaviors:
            if b in self.risk_weights:
                val = self.risk_weights[b]
                score += val
                matched_indicators.append((f"Static: {b}", val))
            elif "IMPORT_SENSITIVE" in b:
                score += 5
                matched_indicators.append((f"Static: Import sensitive module ({b})", 5))

        # Process dynamic behavioral logs (higher weight as they are confirmed executions)
        if dynamic_results:
            for event in dynamic_results:
                cat = event.get("category")
                if cat == "SHELL_EXECUTION":
                    score += 60 # type: ignore
                    matched_indicators.append(("Dynamic: Confirmed Shell Execution", 60))
                elif cat == "NETWORK_CONNECTION":
                    score += 40 # type: ignore
                    matched_indicators.append(("Dynamic: Outbound Network Request", 40))
                elif cat == "RUNTIME_ERROR":
                    # Potentially obfuscated code crashing under patching
                    score += 10 # type: ignore
                    matched_indicators.append(("Dynamic: Runtime Error (Suspicious)", 10))

        # 2. Factor in RAG Similarity
        highest_rag_match = None
        if rag_results:
            highest_rag_match = rag_results[0]
            # Boost score based on similarity to known bad patterns
            if highest_rag_match['score'] > 0.6:
                # Add up to 30 points for strong matches
                boost = int(highest_rag_match['score'] * 30)
                score += boost
                matched_indicators.append((f"Similar to malicious pattern: {highest_rag_match['pattern']['threat']}", boost))
            elif highest_rag_match['score'] > 0.3:
                boost = int(highest_rag_match['score'] * 15)
                score += boost
                matched_indicators.append((f"Likely related to pattern: {highest_rag_match['pattern']['threat']}", boost))

        # Clamp score to 0-100
        final_score = min(100, int(score))

        # 3. Determine Verdict and Confidence
        # Higher confidence if dynamic analysis confirmed findings
        if final_score >= 70:
            verdict = "MALICIOUS"
            confidence = "High" if (len(behaviors) > 2 or dynamic_results) else "Medium"
        elif final_score >= 30:
            verdict = "SUSPICIOUS"
            confidence = "Medium"
        else:
            verdict = "SAFE"
            confidence = "High" if len(behaviors) == 0 else "Low"

        # 4. Generate Reasoning (Simulated LLM Output)
        explanation = self._generate_explanation(verdict, behaviors, highest_rag_match, dynamic_results)

        return {
            "verdict": verdict,
            "score": final_score,
            "reasoning": explanation,
            "confidence": confidence,
            "indicators": matched_indicators
        }

    def _generate_explanation(self, verdict, behaviors, rag_match, dynamic_results=None):
        """Compose a structured explanation for the tool's decision."""
        if not behaviors and not dynamic_results:
            return "Analysis revealed no common indicators of malicious behavior. Package appears benign."

        parts: list[str] = []
        parts.append("AI ANALYSIS REPORT:")
        parts.append("-" * 30)
        
        # Step 1: Static Analysis
        parts.append(f"Step 1: Extracted Static Behaviors")
        if behaviors:
            parts.append(f"The code statically exhibits {len(behaviors)} distinct behavioral indicators, specifically: {', '.join(behaviors)}.")
        else:
            parts.append("No suspicious static patterns found.")
        
        # Step 2: Dynamic Analysis (New)
        parts.append(f"\nStep 2: Dynamic Sandbox Execution")
        if dynamic_results:
            parts.append(f"CRITICAL: Sandbox execution confirmed {len(dynamic_results)} suspicious runtime events.")
            for event in dynamic_results:
                parts.append(f" - [!] {event['category']}: Executed {event['details']}")
        else:
            parts.append("No suspicious activity detected during sandbox execution.")

        parts.append(f"\nStep 3: Threat Pattern Match (RAG)")
        if rag_match and rag_match['score'] > 0.3:
            parts.append(f"Match found in vector database with {int(rag_match['score']*100)}% similarity to '{rag_match['pattern']['threat']}'.")
            parts.append(f"Description: {rag_match['pattern']['description']}")
        else:
            parts.append("No strong matches found in the vector database of known malicious patterns.")

        parts.append(f"\nStep 4: Correlation & Verdict")
        if verdict == "MALICIOUS":
            if dynamic_results:
                parts.append("CRITICAL: The package was confirmed to execute malicious payloads in a sandboxed environment. This is a definitive threat.")
            else:
                parts.append("CRITICAL: The combination of sensitive imports, network activity, and shell execution is highly characteristic of supply-chain attacks.")
        elif verdict == "SUSPICIOUS":
            parts.append("WARNING: While not explicitly identified as malware, the package uses sensitive APIs that are commonly abused. Manual review is recommended.")
        else:
            parts.append("The detected behaviors are common in many legitimate packages. Analysis supports a 'Safe' verdict.")

        return "\n".join(parts)
