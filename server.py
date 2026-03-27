from fastapi import FastAPI, HTTPException # type: ignore
from fastapi.middleware.cors import CORSMiddleware # type: ignore
from pydantic import BaseModel # type: ignore
from pathlib import Path
from detector.engine import DetectionEngine # type: ignore
import os 


app = FastAPI(title="Malicious Package Detection API")

# Add CORS middleware to allow client-side calls
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Adjust this for production!
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize detection engine
# We do this globally to cache the embeddings model
engine = DetectionEngine()

class RemoteAnalysisRequest(BaseModel):
    package_name: str
    registry: str = "npm"  # "npm" or "pypi"

class LocalAnalysisRequest(BaseModel):
    path: str

@app.get("/")
def read_root():
    return {"message": "Malicious Package Detection API is running"}

@app.get("/health")
def health_check():
    return {"status": "healthy", "model_loaded": engine.vector_db.model is not None}

@app.post("/analyze/remote")
async def analyze_remote(request: RemoteAnalysisRequest):
    """Scan a package from npm or pypi registry."""
    if request.registry not in ["npm", "pypi"]:
        raise HTTPException(status_code=400, detail="Invalid registry. Choose 'npm' or 'pypi'.")
    
    result = engine.run(request.package_name, request.registry)
    if "error" in result:
        raise HTTPException(status_code=404, detail=result["error"])
    
    return result

@app.post("/analyze/local")
async def analyze_local(request: LocalAnalysisRequest):
    """Scan a local directory."""
    local_path = Path(request.path)
    if not local_path.exists() or not local_path.is_dir():
        raise HTTPException(status_code=400, detail="Local path does not exist or is not a directory.")
    
    result = engine.run_on_path(local_path, local_path.name)
    if "error" in result:
        raise HTTPException(status_code=404, detail=result["error"])
        
    return result

if __name__ == "__main__":
    import uvicorn # type: ignore
    uvicorn.run(app, host="0.0.0.0", port=8000)
