import os
import json
import numpy as np
import requests
from sentence_transformers import SentenceTransformer
import faiss
from typing import List, Tuple, Dict, Any
import re
from dotenv import load_dotenv

load_dotenv()

class RAGSystem:
    def __init__(self):
        self.embedding_model = SentenceTransformer('all-MiniLM-L6-v2')
        self.dimension = 384  # Dimension of all-MiniLM-L6-v2
        self.index = faiss.IndexFlatIP(self.dimension)  # Inner product for cosine similarity
        self.documents = {}  # doc_id -> document content
        self.metadata = {}   # doc_id -> metadata
        self.chunks = {}     # chunk_id -> (doc_id, chunk_text, start_pos, end_pos)
        self.chunk_counter = 0
        
        # DeepSeek API configuration
        self.deepseek_api_key = os.getenv('DEEPSEEK_API_KEY')
        self.deepseek_api_url = "https://api.deepseek.com/v1/chat/completions"
    
    def chunk_text(self, text: str, chunk_size: int = 500, overlap: int = 50) -> List[Tuple[str, int, int]]:
        """Split text into overlapping chunks with start/end positions"""
        if len(text) <= chunk_size:
            return [(text, 0, len(text))]
        
        chunks = []
        start = 0
        
        while start < len(text):
            end = min(start + chunk_size, len(text))
            
            # Try to break at sentence or word boundary
            if end < len(text):
                # Look for sentence ending
                sentence_end = text.rfind('.', start, end)
                if sentence_end > start + chunk_size // 2:
                    end = sentence_end + 1
                else:
                    # Look for word boundary
                    word_end = text.rfind(' ', start, end)
                    if word_end > start + chunk_size // 2:
                        end = word_end
            
            chunk_text = text[start:end].strip()
            if chunk_text:
                chunks.append((chunk_text, start, end))
            
            if end >= len(text):
                break
                
            start = end - overlap
        
        return chunks
    
    def add_document(self, doc_id: str, content: str, metadata: Dict[str, Any]):
        """Add a document to the RAG system"""
        self.documents[doc_id] = content
        self.metadata[doc_id] = metadata
        
        # Chunk the document
        chunks = self.chunk_text(content)
        
        # Generate embeddings for chunks
        embeddings = []
        for chunk_text, start_pos, end_pos in chunks:
            chunk_id = self.chunk_counter
            self.chunks[chunk_id] = (doc_id, chunk_text, start_pos, end_pos)
            
            # Generate embedding
            embedding = self.embedding_model.encode([chunk_text])[0]
            embeddings.append(embedding)
            
            self.chunk_counter += 1
        
        # Add to FAISS index
        if embeddings:
            embeddings_array = np.array(embeddings).astype('float32')
            # Normalize for cosine similarity
            faiss.normalize_L2(embeddings_array)
            self.index.add(embeddings_array)
    
    def remove_document(self, doc_id: str):
        """Remove a document from the RAG system"""
        if doc_id in self.documents:
            del self.documents[doc_id]
            del self.metadata[doc_id]
            
            # Note: FAISS doesn't support efficient removal, so we'd need to rebuild
            # For now, we'll mark chunks as deleted
            chunks_to_remove = []
            for chunk_id, (chunk_doc_id, _, _, _) in self.chunks.items():
                if chunk_doc_id == doc_id:
                    chunks_to_remove.append(chunk_id)
            
            for chunk_id in chunks_to_remove:
                del self.chunks[chunk_id]
    
    def search_similar_chunks(self, query: str, doc_ids: List[str] = None, top_k: int = 5) -> List[Tuple[str, str, float, int, int]]:
        """Search for similar chunks to the query"""
        if not self.chunks:
            return []
        
        # Generate query embedding
        query_embedding = self.embedding_model.encode([query])[0]
        query_embedding = query_embedding.astype('float32').reshape(1, -1)
        faiss.normalize_L2(query_embedding)
        
        # Search in FAISS index
        scores, indices = self.index.search(query_embedding, min(top_k * 3, self.index.ntotal))
        
        results = []
        for score, idx in zip(scores[0], indices[0]):
            if idx == -1:  # Invalid index
                continue
                
            # Find the chunk corresponding to this index
            chunk_id = None
            current_idx = 0
            for cid in sorted(self.chunks.keys()):
                if current_idx == idx:
                    chunk_id = cid
                    break
                current_idx += 1
            
            if chunk_id is None or chunk_id not in self.chunks:
                continue
                
            doc_id, chunk_text, start_pos, end_pos = self.chunks[chunk_id]
            
            # Filter by doc_ids if provided
            if doc_ids and doc_id not in doc_ids:
                continue
            
            results.append((doc_id, chunk_text, float(score), start_pos, end_pos))
        
        # Sort by score and return top_k
        results.sort(key=lambda x: x[2], reverse=True)
        return results[:top_k]
    
    def call_deepseek_api(self, prompt: str) -> str:
        """Call DeepSeek API to generate an answer"""
        if not self.deepseek_api_key:
            return "DeepSeek API key not configured. Please set DEEPSEEK_API_KEY environment variable."
        
        headers = {
            "Authorization": f"Bearer {self.deepseek_api_key}",
            "Content-Type": "application/json"
        }
        
        data = {
            "model": "deepseek-chat",
            "messages": [
                {
                    "role": "system",
                    "content": "You are a helpful AI assistant for RISK company's knowledge base. Answer questions based on the provided context accurately and concisely. If the context doesn't contain enough information to answer the question, say so clearly."
                },
                {
                    "role": "user",
                    "content": prompt
                }
            ],
            "temperature": 0.3,
            "max_tokens": 1000
        }
        
        try:
            response = requests.post(self.deepseek_api_url, headers=headers, json=data, timeout=30)
            response.raise_for_status()
            
            result = response.json()
            return result['choices'][0]['message']['content']
        
        except requests.exceptions.RequestException as e:
            return f"Error calling DeepSeek API: {str(e)}"
        except KeyError as e:
            return f"Unexpected API response format: {str(e)}"
        except Exception as e:
            return f"Error generating answer: {str(e)}"
    
    def get_answer(self, question: str, doc_ids: List[str] = None) -> Tuple[str, List[Dict]]:
        """Get an answer to a question using RAG"""
        # Search for relevant chunks
        similar_chunks = self.search_similar_chunks(question, doc_ids, top_k=5)
        
        if not similar_chunks:
            return "I couldn't find any relevant information in the knowledge base to answer your question.", []
        
        # Prepare context from similar chunks
        context_parts = []
        citations = []
        
        for i, (doc_id, chunk_text, score, start_pos, end_pos) in enumerate(similar_chunks):
            metadata = self.metadata.get(doc_id, {})
            
            # Add to context
            context_parts.append(f"[Source {i+1}]: {chunk_text}")
            
            # Prepare citation
            citation = {
                'id': i + 1,
                'doc_id': doc_id,
                'filename': metadata.get('filename', metadata.get('title', f'Document {doc_id}')),
                'chunk_text': chunk_text,
                'start_pos': start_pos,
                'end_pos': end_pos,
                'score': score,
                'type': metadata.get('type', 'document')
            }
            citations.append(citation)
        
        context = "\n\n".join(context_parts)
        
        # Create prompt for DeepSeek
        prompt = f"""Based on the following context from RISK company's knowledge base, please answer the question.

Context:
{context}

Question: {question}

Instructions:
1. Answer based only on the provided context
2. If the context doesn't contain enough information, say so clearly
3. Use specific details from the sources when possible
4. Reference sources using [Source X] notation when citing information
5. Be concise but comprehensive

Answer:"""
        
        # Get answer from DeepSeek
        answer = self.call_deepseek_api(prompt)
        
        return answer, citations
    
    def get_document_info(self, doc_id: str) -> Dict[str, Any]:
        """Get information about a specific document"""
        if doc_id not in self.documents:
            return None
        
        return {
            'doc_id': doc_id,
            'content': self.documents[doc_id],
            'metadata': self.metadata[doc_id]
        }