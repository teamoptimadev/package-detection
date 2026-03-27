import json
import numpy as np # type: ignore
import os
from pathlib import Path

# Try to use sklearn for similarity, otherwise fallback to numpy manual
try:
    from sklearn.metrics.pairwise import cosine_similarity # type: ignore
    HAS_SKLEARN = True
except ImportError:
    HAS_SKLEARN = False

# Use sentence-transformers for real embeddings
try:
    from sentence_transformers import SentenceTransformer # type: ignore
    HAS_TRANSFORMERS = True
except ImportError:
    HAS_TRANSFORMERS = False

class VectorDB:
    def __init__(self, patterns_path):
        self.patterns_path = patterns_path
        self.patterns = self._load_patterns()
        self.model = None
        self.embeddings = None
        
        if HAS_TRANSFORMERS:
            try:
                # Use a small, fast model
                self.model = SentenceTransformer('all-MiniLM-L6-v2')
                self._generate_embeddings()
            except:
                self.model = None
        
    def _load_patterns(self):
        if not os.path.exists(self.patterns_path):
            return []
        with open(self.patterns_path, 'r') as f:
            try:
                return json.load(f)
            except:
                return []

    def _generate_embeddings(self):
        if not self.model or not self.patterns:
            return
        texts = [p['pattern'] for p in self.patterns]
        try:
            self.embeddings = self.model.encode(texts) # type: ignore
        except:
            self.embeddings = None

    def search_similar(self, query, top_k=1):
        """Find most similar malicious pattern."""
        if not self.patterns:
            return []
            
        if self.model and self.embeddings is not None:
            try:
                query_embedding = self.model.encode([query])
                
                if HAS_SKLEARN:
                    similarities = cosine_similarity(self.embeddings, query_embedding.reshape(1, -1)).flatten()
                else:
                    # Manual cosine similarity if sklearn is missing
                    # Compute dot product
                    dot_product = np.dot(self.embeddings, query_embedding.T).flatten()
                    norms = np.linalg.norm(self.embeddings, axis=1) * np.linalg.norm(query_embedding)
                    similarities = dot_product / (norms + 1e-9)
                
                # Sort by score
                idx = np.argsort(similarities)[-top_k:][::-1]
                
                results = []
                for i in idx:
                    results.append({
                        "pattern": self.patterns[i],
                        "score": float(similarities[i])
                    })
                return results
            except:
                return self._fallback_search(query, top_k)
        else:
            return self._fallback_search(query, top_k)

    def _fallback_search(self, query, top_k):
        """Keyword-based fallback if no model is available."""
        results = []
        q_words = set(query.lower().split())
        for p in self.patterns:
            p_words = set(p['pattern'].lower().split())
            intersection = p_words.intersection(q_words)
            union = p_words.union(q_words)
            score = len(intersection) / len(union) if union else 0
            results.append({"pattern": p, "score": score})
        
        results.sort(key=lambda x: x['score'], reverse=True)
        return results[:top_k] # type: ignore
