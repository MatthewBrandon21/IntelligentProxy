#uvicorn main:app --reload
#pip install "fastapi[all]"

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

app = FastAPI()
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

@app.get("/api")
async def api():
  return {"message": "Hello from FastAPI"}

@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

@app.get("/login", response_class=HTMLResponse)
async def login(request: Request):
    return templates.TemplateResponse("page3.html", {"request": request})

@app.get("/home", response_class=HTMLResponse)
async def home(request: Request):
    return templates.TemplateResponse("page2.html", {"request": request})

@app.get("/register", response_class=HTMLResponse)
async def register(request: Request):
    return templates.TemplateResponse("page1.html", {"request": request})

@app.get("/documentation", response_class=HTMLResponse)
async def documentation(request: Request):
    return templates.TemplateResponse("page5.html", {"request": request})

@app.get("/singlepageapplication", response_class=HTMLResponse)
async def singlepageapplication(request: Request):
    return templates.TemplateResponse("page4.html", {"request": request})

@app.exception_handler(404)
async def custom_404_handler(request, __):
    return templates.TemplateResponse("404.html", {"request": request})
