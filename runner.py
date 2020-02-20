import uvicorn
from fencex.app import app

if __name__ == "__main__":
    uvicorn.run(app, port=8080)
