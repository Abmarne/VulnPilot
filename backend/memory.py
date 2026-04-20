import os
import json
import chromadb
from chromadb.config import Settings
from typing import List, Dict, Any, Optional

class VectorMemoryManager:
    """
    Manages Long-Term Memory (LTM) using ChromaDB for semantic security knowledge retrieval.
    """
    def __init__(self, persist_directory: str = ".data/chroma"):
        self.persist_directory = persist_directory
        # Ensure directory exists
        os.makedirs(persist_directory, exist_ok=True)
        
        self.client = chromadb.PersistentClient(path=persist_directory)
        # Collection for security findings
        self.collection = self.client.get_or_create_collection(
            name="security_knowledge",
            metadata={"hnsw:space": "cosine"} # Semantic similarity
        )

    def save_finding(self, finding: Dict[str, Any]):
        """Indexes a verified finding into the vector store."""
        finding_id = finding.get("id") or f"kb_{os.urandom(4).hex()}"
        
        # The 'document' is the context we want to search by (semantic key)
        # We combine vulnerability type and the explanation or code snippet
        document = f"Type: {finding.get('vulnerability_type')}\n" \
                   f"Context: {finding.get('explanation', '')}\n" \
                   f"Impact: {finding.get('impact', '')}"
        
        metadata = {
            "vulnerability_type": finding.get("vulnerability_type", "unknown"),
            "payload": str(finding.get("manual_poc", "")),
            "remediation": str(finding.get("remediation_steps", "")),
            "success_rate": 1.0,
            "failure_count": 0,
            "total_uses": 1
        }
        
        self.collection.add(
            ids=[finding_id],
            documents=[document],
            metadatas=[metadata]
        )

    def recall_relevant(self, query_context: str, limit: int = 3) -> List[Dict[str, Any]]:
        """Retrieves semantic matches for the current mission context."""
        try:
            results = self.collection.query(
                query_texts=[query_context],
                n_results=limit
            )
            
            recalled = []
            if results and results['metadatas']:
                for i in range(len(results['metadatas'][0])):
                    meta = results['metadatas'][0][i]
                    # Efficacy Pruning Check:
                    if meta.get("failure_count", 0) > 5 and meta.get("success_rate", 1.0) < 0.2:
                        continue # Prune from current context
                        
                    recalled.append({
                        "document": results['documents'][0][i],
                        "metadata": meta
                    })
            return recalled
        except Exception as e:
            print(f"[MEMORY] Recall failed: {e}")
            return []

    def update_efficacy(self, knowledge_id: str, was_successful: bool):
        """Updates the success/failure tracking for an entry."""
        results = self.collection.get(ids=[knowledge_id])
        if not results or not results['metadatas']:
            return
            
        meta = results['metadatas'][0]
        total = meta.get("total_uses", 1) + 1
        failures = meta.get("failure_count", 0) + (0 if was_successful else 1)
        
        # Calculate success rate
        # (Total - Failures) / Total
        new_rate = (total - failures) / total
        
        self.collection.update(
            ids=[knowledge_id],
            metadatas=[{
                "success_rate": new_rate,
                "failure_count": failures,
                "total_uses": total
            }]
        )

    def prune_low_efficacy(self):
        """Hard deletion of low-efficacy items."""
        # In Chroma, we'd query by metadata but simple filter is safer
        # This is typically run as a maintenance task
        pass
