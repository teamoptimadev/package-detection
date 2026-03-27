import os
from pathlib import Path
from utils.downloader import PackageDownloader # type: ignore
from parser.ast_parser import ASTParser # type: ignore
from parser.behavior_extractor import BehaviorExtractor # type: ignore
from rag.vector_db import VectorDB # type: ignore
from llm.analyzer import LLMAnalyzer # type: ignore
from detector.sandbox import SandboxManager # type: ignore

class DetectionEngine:
    def __init__(self):
        self.downloader = PackageDownloader()
        self.ast_parser = ASTParser()
        self.behavior_extractor = BehaviorExtractor()
        self.sandbox = SandboxManager()
        
        # Paths
        base_path = Path(__file__).parent.parent
        patterns_path = base_path / "rag" / "patterns.json"
        self.vector_db = VectorDB(str(patterns_path))
        self.analyzer = LLMAnalyzer()

    def run(self, package_name, registry="npm"):
        """Run the full detection pipeline on a package."""
        
        # 1. Download & Extract
        try:
            if registry == "npm":
                extract_dir = self.downloader.download_npm(package_name)
            else:
                extract_dir = self.downloader.download_pypi(package_name)
            
            return self.run_on_path(extract_dir, package_name, registry)
        except Exception as e:
            return {"error": f"Failed to download package: {str(e)}"}

    def run_on_path(self, path, package_name, registry="local"):
        """Run analysis on an existing local directory."""
        path = Path(path)
        
        # 1. Get files & source code
        source_files = self.downloader.get_source_files(path)
        if not source_files:
            return {"error": "No source files found in package."}

        all_tokens = []
        for file_path in source_files:
            tokens = self.ast_parser.parse_file(file_path)
            all_tokens.extend(tokens)

        # 2. Extract Behaviors
        behaviors = self.behavior_extractor.extract(all_tokens)
        behavior_description = self.behavior_extractor.to_natural_language(behaviors)

        # 3. RAG Search
        rag_results = self.vector_db.search_similar(behavior_description, top_k=1)

        # 4. Dynamic Analysis
        dynamic_results = self.sandbox.run_dynamic_analysis(path)

        # 5. LLM Analysis
        analysis_result = self.analyzer.analyze(behaviors, rag_results, dynamic_results)

        return {
            "package_name": package_name,
            "registry": registry,
            "behaviors": behaviors,
            "behavior_description": behavior_description,
            "rag_match": rag_results[0] if rag_results else None,
            "dynamic_analysis": dynamic_results,
            "analysis": analysis_result
        }
