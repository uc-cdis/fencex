import uvicorn

from fencex.asgi import app

if __name__ == "__main__":
    uvicorn.run(app, port=8080)
