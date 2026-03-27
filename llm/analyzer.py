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

    def analyze(self, behaviors, rag_results):
        """Perform simulated LLM analysis of the package behaviors and RAG matches."""
        
        # 1. Calculate Base Risk Score
        score = 0
        matched_indicators = []
        for b in behaviors:
            if b in self.risk_weights:
                val = self.risk_weights[b]
                score += val
                matched_indicators.append((b, val))
            elif "IMPORT_SENSITIVE" in b:
                score += 5
                matched_indicators.append((f"Import sensitive module ({b})", 5))

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
        if final_score >= 70:
            verdict = "MALICIOUS"
            confidence = "High" if len(behaviors) > 2 else "Medium"
        elif final_score >= 30:
            verdict = "SUSPICIOUS"
            confidence = "Medium"
        else:
            verdict = "SAFE"
            confidence = "High" if len(behaviors) == 0 else "Low"

        # 4. Generate Reasoning (Simulated LLM Output)
        explanation = self._generate_explanation(verdict, behaviors, highest_rag_match)

        return {
            "verdict": verdict,
            "score": final_score,
            "reasoning": explanation,
            "confidence": confidence,
            "indicators": matched_indicators
        }

    def _generate_explanation(self, verdict, behaviors, rag_match):
        """Compose a structured explanation for the tool's decision."""
        if not behaviors:
            return "Analysis revealed no common indicators of malicious behavior. Package appears benign."

        parts: list[str] = []
        parts.append("AI ANALYSIS REPORT:")
        parts.append("-" * 30)
        
        # Step-by-step reasoning
        parts.append(f"Step 1: Extracted Behaviors")
        parts.append(f"The code exhibits {len(behaviors)} distinct behavioral indicators, specifically: {', '.join(behaviors)}.")
        
        parts.append(f"\nStep 2: Threat Pattern Match (RAG)")
        if rag_match and rag_match['score'] > 0.3:
            parts.append(f"Match found in vector database with {int(rag_match['score']*100)}% similarity to '{rag_match['pattern']['threat']}'.")
            parts.append(f"Description: {rag_match['pattern']['description']}")
        else:
            parts.append(f"No strong matches found in the vector database of known malicious patterns.")

        parts.append(f"\nStep 3: Correlation & Verdict")
        if verdict == "MALICIOUS":
            parts.append("CRITICAL: The combination of sensitive imports, network activity, and shell execution is highly characteristic of supply-chain attacks. The risk of data exfiltration or credential theft is extremely high.")
        elif verdict == "SUSPICIOUS":
            parts.append("WARNING: While not explicitly identified as malware, the package uses sensitive APIs that are commonly abused by malicious actors. Manual review of the source code is recommended.")
        else:
            parts.append("The detected behaviors are common in many legitimate packages. The low similarity score further supports a 'Safe' verdict.")

        return "\n".join(parts)
