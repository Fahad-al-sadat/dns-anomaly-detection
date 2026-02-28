import os, datetime, secrets
from fastapi import FastAPI, Depends, HTTPException, status, Request, Form
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, FileResponse, RedirectResponse
from pydantic import BaseModel
from dns_engine import DNSEngine
from behavior import BehaviorEngine
from collections import deque
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware
from urllib.parse import urlparse

app = FastAPI()
app.mount("/static", StaticFiles(directory=os.path.join(os.path.dirname(__file__), "static")), name="static")

templates = Jinja2Templates(directory="templates")

# CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.add_middleware(
    SessionMiddleware,
    secret_key="super-secret-key"
)

# Engines Initialization
engine = DNSEngine()
behavior = BehaviorEngine()

# In-memory log storage
logs = deque(maxlen=200)

class DNSRequest(BaseModel):
    ip: str
    domain: str

#API ENDPOINTS

@app.post("/check")
def check_dns(req: DNSRequest, request: Request):
    client_ip = request.client.host
    ml_pred, ml_prob = engine.ml_check(req.domain)
    behavior_score = behavior.analyze(client_ip, req.domain)

    # Logic: Anomaly if ML predicts it OR behavior is suspicious
    if ml_pred == 1 or behavior_score >= 2:
        status = "ANOMALY"
    else:
        status = "NORMAL"

    log_entry = {
        "time": datetime.datetime.now().strftime("%H:%M:%S"),
        "ip": client_ip,
        "domain": req.domain,
        "status": status,
        "ml_prob": float(ml_prob),
        "behavior": behavior_score
    }

    logs.appendleft(log_entry)
    return log_entry

@app.get("/api/stats")
def get_stats():
    """This endpoint feeds the real-time chart and stat cards."""
    total = len(logs)
    anomalies = sum(1 for log in logs if log["status"] == "ANOMALY")
    threat_level = (anomalies / total * 100) if total > 0 else 0
    
    return {
        "total_requests": total,
        "anomalies": anomalies,
        "threat_level": round(threat_level, 1),
        "logs": list(logs)
    }

# RESET ENDPOINT
@app.post("/api/reset")
def reset_logs():
    logs.clear()
    return {"status": "success", "message": "Logs cleared"}

# DASHBOARD UI

USERS = {
    "admin": {"password": "admin123", "role": "admin"},
    "Fahad": {"password": "user123", "role": "user"}
}

@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})


@app.post("/login", response_class=HTMLResponse)
def login(request: Request, username: str = Form(...), password: str = Form(...)):
    user = USERS.get(username)

    if not user or user["password"] != password:
        return templates.TemplateResponse(
            "login.html",
            {"request": request, "error": "Invalid credentials"}
        )

    request.session["user"] = username
    request.session["role"] = user["role"]

    return RedirectResponse("/dashboard", status_code=302)

@app.get("/logout")
def logout(request: Request):
    request.session.clear()
    return RedirectResponse("/login", status_code=302)

@app.get("/dashboard", response_class=HTMLResponse)
def dashboard(request: Request):
    if "user" not in request.session:
        return RedirectResponse("/login", status_code=302)

    return templates.TemplateResponse(
        "index.html",
        {
            "request": request,
            "username": request.session.get("user"),
            "role": request.session.get("role")
        }
    )

@app.get("/warning", response_class=HTMLResponse)
async def warning_page(request: Request, domain: str = "unknown"):
    return templates.TemplateResponse(request, "warning.html", {"domain": domain})

@app.get("/blocked")
async def get_blocked_page(request: Request, url: str = "Unknown"):
    return templates.TemplateResponse("blocked_ui.html", {"request": request, "url": url})
