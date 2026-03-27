import os
from pathlib import Path
from utils.downloader import PackageDownloader # type: ignore
from parser.ast_parser import ASTParser # type: ignore
from parser.behavior_extractor import BehaviorExtractor # type: ignore
from rag.vector_db import VectorDB # type: ignore
from llm.analyzer import LLMAnalyzer # type: ignore

class DetectionEngine:
    def __init__(self):
        self.downloader = PackageDownloader()
        self.ast_parser = ASTParser()
        self.behavior_extractor = BehaviorExtractor()
        
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
        except Exception as e:
            return {"error": f"Failed to download package: {str(e)}"}

        # 2. Get files & source code
        source_files = self.downloader.get_source_files(extract_dir)
        if not source_files:
            return {"error": "No source files found in package."}

        all_tokens = []
        for file_path in source_files:
            tokens = self.ast_parser.parse_file(file_path)
            all_tokens.extend(tokens)

        # 3. Extract Behaviors
        behaviors = self.behavior_extractor.extract(all_tokens)
        behavior_description = self.behavior_extractor.to_natural_language(behaviors)

        # 4. RAG Search
        rag_results = self.vector_db.search_similar(behavior_description, top_k=1)

        # 5. LLM Analysis
        analysis_result = self.analyzer.analyze(behaviors, rag_results)

        # Cleanup (Optional)
        # shutil.rmtree(extract_dir)

        return {
            "package_name": package_name,
            "registry": registry,
            "behaviors": behaviors,
            "behavior_description": behavior_description,
            "rag_match": rag_results[0] if rag_results else None,
            "analysis": analysis_result
        }
