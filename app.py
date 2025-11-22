from __future__ import annotations
from datetime import datetime, timedelta
from pathlib import Path
from typing import Generator, Optional
import os, uuid, secrets, shutil
import subprocess
import logging
from logging.handlers import RotatingFileHandler
import smtplib
from email.message import EmailMessage

from fastapi import FastAPI, Request, Depends, Form, UploadFile, File, HTTPException, status
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.templating import Jinja2Templates
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm

from sqlalchemy import Column, Integer, String, Boolean, DateTime, ForeignKey, create_engine, select
from sqlalchemy.orm import declarative_base, sessionmaker, Session, relationship

from passlib.context import CryptContext
from jose import jwt, JWTError
from email_validator import validate_email, EmailNotValidError

# BASIC CONFIG 
BASE_DIR = Path(__file__).resolve().parent
TEMPLATE_DIR = BASE_DIR / "templates"
UPLOAD_ROOT = BASE_DIR / "uploads"  # Only used when PERSIST_UPLOADS=1
TEMPLATE_DIR.mkdir(exist_ok=True)
UPLOAD_ROOT.mkdir(exist_ok=True)

templates = Jinja2Templates(directory=str(TEMPLATE_DIR))

PUBLIC_BASE_URL = os.getenv("PUBLIC_BASE_URL", "http://127.0.0.1:8000")
PERSIST_UPLOADS = os.getenv("PERSIST_UPLOADS", "0") == "1"

SECRET_KEY = os.getenv("SECRET_KEY", "CHANGE-ME-TO-RANDOM")
ALGO = "HS256"
ACCESS_TOKEN_EXPIRE_MIN = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES"))
BOOT_ID = secrets.token_urlsafe(16)  # Changes after restart, old tokens become invalid

# Password hash: Argon2 (no 72-byte limit)
pwd = CryptContext(schemes=["argon2"], deprecated="auto")

# Temp file root directory (used in non-persistent mode)
TMP_ROOT = Path("/tmp/webapp")
TMP_ROOT.mkdir(parents=True, exist_ok=True)

# Logging
LOG_ROOT = BASE_DIR / "logs"
LOG_ROOT.mkdir(exist_ok=True)

DEBUG_ERRORS = os.getenv("DEBUG_ERRORS", "0") == "1"

def init_logging():
    log_file = LOG_ROOT / "webapp.log"
    handler = RotatingFileHandler(log_file, maxBytes=5_000_000, backupCount=3, encoding="utf-8")
    fmt = logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s")
    handler.setFormatter(fmt)

    root = logging.getLogger()
    root.setLevel(logging.INFO)
    # Avoid adding duplicate handlers (hot reload scenario)
    if not any(isinstance(h, RotatingFileHandler) for h in root.handlers):
        root.addHandler(handler)

init_logging()

# EMAIL CONFIG 
MAIL_FROM = os.getenv("MAIL_FROM")              # Sender display address, e.g. no-reply@example.com
MAIL_SUBJECT_PREFIX = os.getenv("MAIL_SUBJECT_PREFIX", "[WebApp] ")

SMTP_HOST = os.getenv("SMTP_HOST")              # SMTP server, e.g. smtp.gmail.com
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))  # Port, TLS commonly uses 587
SMTP_USER = os.getenv("SMTP_USER")              # Login username
SMTP_PASS = os.getenv("SMTP_PASS", "")          # Login password/app-specific password
SMTP_TLS  = os.getenv("SMTP_TLS", "1") == "1"   # Use starttls or not
SMTP_SSL  = os.getenv("SMTP_SSL", "0") == "1"   # Use direct SSL or not (e.g. 465)

def send_verification_email(to_email: str, verify_url: str) -> bool:
    """
    Send verification email.
    Return True if sent successfully; False if not sent (not configured or failed, frontend can still manually open verify_url).
    """
    if not SMTP_HOST or not SMTP_USER:
        logging.warning("SMTP not configured, skip sending verification email, only returning verify_url.")
        return False

    sender = MAIL_FROM or SMTP_USER
    subject = MAIL_SUBJECT_PREFIX + "Email verification"

    text = (
        f"Hello!\n\n"
        f"Please click the link below to complete email verification (valid for 24 hours):\n"
        f"{verify_url}\n\n"
        f"If this was not initiated by you, please ignore this email.\n"
    )
    html = f"""
    <html><body>
      <p>Hello!</p>
      <p>Please click the button below to complete email verification (valid for 24 hours):</p>
      <p>
        <a href="{verify_url}"
           style="display:inline-block;padding:10px 18px;background:#16a34a;
                  color:#ffffff;text-decoration:none;border-radius:4px;">
          Verify email
        </a>
      </p>
      <p>If the button does not work, copy the link below into your browser:</p>
      <p><a href="{verify_url}">{verify_url}</a></p>
      <p>If this was not initiated by you, please ignore this email.</p>
    </body></html>
    """

    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = sender
    msg["To"] = to_email
    msg.set_content(text)
    msg.add_alternative(html, subtype="html")

    try:
        if SMTP_SSL:
            with smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT, timeout=15) as s:
                if SMTP_USER:
                    s.login(SMTP_USER, SMTP_PASS)
                s.send_message(msg)
        else:
            with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=15) as s:
                if SMTP_TLS:
                    s.starttls()
                if SMTP_USER:
                    s.login(SMTP_USER, SMTP_PASS)
                s.send_message(msg)
        logging.info("Verification email sent to %s", to_email)
        return True
    except Exception as e:
        logging.error("Failed to send verification email to=%s: %s", to_email, e)
        return False

# FastAPI APP 
app = FastAPI(title="WebApp", docs_url=None, redoc_url=None, openapi_url=None)
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# DATABASE & MODELS 
DATABASE_URL = f"sqlite:///{BASE_DIR/'app.db'}"
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
Base = declarative_base()

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    email = Column(String(255), unique=True, index=True, nullable=False)
    password_hash = Column(String(255), nullable=False)
    is_verified = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    uploads = relationship("Upload", back_populates="user")

class Upload(Base):
    __tablename__ = "uploads"
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    filename = Column(String(255), nullable=False)
    original_name = Column(String(255), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    user = relationship("User", back_populates="uploads")

class Task(Base):
    __tablename__ = "tasks"
    id = Column(String(64), primary_key=True)           # uuid
    user_id = Column(Integer, ForeignKey("users.id"))
    upload_id = Column(Integer, default=0)              # Used in persistent mode; 0 in temp mode
    status = Column(String(32), default="queued")       # queued|running|completed|failed
    result_path = Column(String(255), nullable=True)    # Result file name
    created_at = Column(DateTime, default=datetime.utcnow)

Base.metadata.create_all(bind=engine)

def get_db() -> Generator[Session, None, None]:
    db = SessionLocal()
    try: yield db
    finally: db.close()

#  SECURITY HELPERS 
def hash_pw(p: str) -> str:
    return pwd.hash(p)

def verify_pw(p: str, h: str) -> bool:
    return pwd.verify(p, h)

def create_token(sub: str, minutes: int) -> str:
    payload = {
        "sub": sub,
        "boot": BOOT_ID,
        "exp": datetime.utcnow() + timedelta(minutes=minutes),
        "iat": datetime.utcnow(),
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGO)

def decode_token(token: str) -> str:
    data = jwt.decode(token, SECRET_KEY, algorithms=[ALGO])
    if data.get("boot") != BOOT_ID:
        raise JWTError("stale token")
    return data["sub"]

def get_current_user(db: Session = Depends(get_db), token: str = Depends(oauth2_scheme)) -> User:
    try:
        email = decode_token(token)
    except JWTError:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid or expired token")
    user = db.execute(select(User).where(User.email == email)).scalar_one_or_none()
    if not user:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "User not found")
    return user

# For image routes: support both Authorization header and ?token=...
def auth_user_from_request(request: Request, db: Session) -> User:
    auth = request.headers.get("authorization") or request.headers.get("Authorization")
    token = None
    if auth and auth.lower().startswith("bearer "):
        token = auth.split(" ", 1)[1].strip()
    if not token:
        token = request.query_params.get("token")
    if not token:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Missing token")
    try:
        email = decode_token(token)
    except JWTError:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid or expired token")
    user = db.execute(select(User).where(User.email == email)).scalar_one_or_none()
    if not user:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "User not found")
    return user

# UTIL FUNCTIONS 
def user_dir(user_id: int) -> Path:
    p = UPLOAD_ROOT / f"user_{user_id}"
    p.mkdir(parents=True, exist_ok=True)
    return p

def user_tmp_dir(user_id: int) -> Path:
    p = TMP_ROOT / f"user_{user_id}"
    p.mkdir(parents=True, exist_ok=True)
    return p

# detection with external shell (e.g. YOLO)
def run_detector(src_path: Path, out_path: Path, timeout: int = None) -> tuple[int, str]:
    detect_sh = os.getenv("DETECT_SH")
    if not detect_sh or not Path(detect_sh).exists():
        return 127, "DETECT_SH is not configured or script does not exist"

    out_path.parent.mkdir(parents=True, exist_ok=True)
    cmd = [detect_sh, str(src_path), str(out_path)]
    try:
        result = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=timeout or int(os.getenv("DETECT_TIMEOUT", "120"))
        )
        return result.returncode, result.stdout
    except subprocess.TimeoutExpired as te:
        return 124, f"Timeout: {te}"
    except Exception as e:
        return 1, f"Unknown error: {e}"

def user_log_dir(user_id: int) -> Path:
    p = LOG_ROOT / f"user_{user_id}"
    p.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(p, 0o700)  # Only local user can read/write
    except Exception:
        pass
    return p

def write_task_log(user_id: int, task_id: str, text: str) -> Path:
    """Write detailed output of a single task to logs/user_<uid>/task_<taskid>.log"""
    p = user_log_dir(user_id) / f"task_{task_id}.log"
    try:
        with p.open("a", encoding="utf-8") as f:
            f.write(text if text.endswith("\n") else text + "\n")
    except Exception as e:
        logging.warning("Failed to write task log user=%s task=%s: %s", user_id, task_id, e)
    return p

#  PAGES (LOGIN / REGISTER / DASHBOARD) 
@app.get("/", response_class=HTMLResponse)
def login_page(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})

@app.get("/register", response_class=HTMLResponse)
def register_page(request: Request):
    return templates.TemplateResponse("register.html", {"request": request})

@app.get("/dashboard", response_class=HTMLResponse)
def dashboard_page(request: Request):
    return templates.TemplateResponse("dashboard.html", {"request": request})

# HEALTH / HEARTBEAT (used for redirecting to login) 
@app.get("/auth/ping")
def auth_ping(me: User = Depends(get_current_user)):
    return {"ok": True, "exp_minutes": ACCESS_TOKEN_EXPIRE_MIN}

#  REGISTER / VERIFY / LOGIN 
@app.post("/register/send")
def register_send(
    email: str = Form(...),
    password: str = Form(...),
    password2: str = Form(...),
    db: Session = Depends(get_db)
):
    try:
        email = validate_email(email, check_deliverability=False).email
    except EmailNotValidError as e:
        raise HTTPException(400, str(e))
    if password != password2:
        raise HTTPException(400, "The two passwords do not match")
    if len(password) < 8:
        raise HTTPException(400, "Password must be at least 8 characters")
    existed = db.execute(select(User).where(User.email == email)).scalar_one_or_none()
    if existed:
        raise HTTPException(400, "This email is already registered")

    user = User(email=email, password_hash=hash_pw(password), is_verified=False)
    db.add(user); db.commit()

    token = create_token(email, minutes=60*24)
    verify_url = f"{PUBLIC_BASE_URL}/verify?token={token}"

    # Send verification email (if sending fails, still return verify_url to frontend)
    sent = send_verification_email(email, verify_url)
    return {"verify_url": verify_url, "email_sent": sent}

@app.post("/register/resend")
def register_resend(email: str = Form(...), db: Session = Depends(get_db)):
    user = db.execute(select(User).where(User.email == email)).scalar_one_or_none()
    if not user:
        raise HTTPException(404, "User does not exist")
    if user.is_verified:
        raise HTTPException(400, "This email is already verified, no need to resend")
    token = create_token(email, minutes=60*24)
    verify_url = f"{PUBLIC_BASE_URL}/verify?token={token}"

    sent = send_verification_email(email, verify_url)
    return {"verify_url": verify_url, "email_sent": sent}

@app.get("/verify")
def verify_email(token: str, db: Session = Depends(get_db)):
    try:
        email = decode_token(token)
    except JWTError:
        raise HTTPException(400, "Verification link is invalid or has expired")
    user = db.execute(select(User).where(User.email == email)).scalar_one_or_none()
    if not user:
        raise HTTPException(404, "User does not exist")
    user.is_verified = True
    db.commit()

    html = """
    <html><meta charset="utf-8"><body>
    <h3>Email verification succeeded! This page will close automatically in <span id='t'>5</span> seconds.</h3>
    <script>
      let n=5; setInterval(()=>{n--; if(n<=0) window.close(); else document.getElementById('t').textContent=n;},1000);
    </script>
    </body></html>
    """
    return HTMLResponse(html)

@app.post("/token")
def login(form: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    email = form.username
    user = db.execute(select(User).where(User.email == email)).scalar_one_or_none()
    if not user or not verify_pw(form.password, user.password_hash):
        raise HTTPException(400, "Incorrect email or password")
    if not user.is_verified:
        raise HTTPException(403, "Email is not verified yet, please verify first")
    token = create_token(email, minutes=ACCESS_TOKEN_EXPIRE_MIN)
    return {"access_token": token, "token_type": "bearer"}

# UPLOAD / PREVIEW 
@app.post("/upload")
async def upload(
    file: UploadFile = File(...),
    me: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    ext = (Path(file.filename).suffix or "").lower()
    if ext not in [".jpg", ".jpeg", ".png", ".bmp", ".gif"]:
        raise HTTPException(400, "Only image files are allowed")

    if PERSIST_UPLOADS:
        safe = f"{uuid.uuid4().hex}{ext}"
        dest = user_dir(me.id) / safe
        with dest.open("wb") as f:
            shutil.copyfileobj(file.file, f)
        rec = Upload(user_id=me.id, filename=safe, original_name=file.filename)
        db.add(rec); db.commit(); db.refresh(rec)
        return {"mode": "persist", "upload_id": rec.id, "preview_url": f"/files/{rec.id}"}
    else:
        temp_id = uuid.uuid4().hex + ext
        dest = user_tmp_dir(me.id) / temp_id
        with dest.open("wb") as f:
            shutil.copyfileobj(file.file, f)
        return {"mode": "temp", "temp_id": temp_id, "preview_url": f"/temp/{temp_id}"}

@app.get("/files/{upload_id}")
def get_file(upload_id: int, request: Request, db: Session = Depends(get_db)):
    me = auth_user_from_request(request, db)
    u: Optional[Upload] = db.get(Upload, upload_id)
    if not u or u.user_id != me.id:
        raise HTTPException(404, "File not found")
    path = user_dir(me.id) / u.filename
    return FileResponse(path, filename=u.original_name)

@app.get("/temp/{temp_id}")
def get_temp(temp_id: str, request: Request, db: Session = Depends(get_db)):
    me = auth_user_from_request(request, db)
    path = user_tmp_dir(me.id) / temp_id
    if not path.exists():
        raise HTTPException(404, "Temporary file does not exist")
    return FileResponse(path, filename=Path(temp_id).name)

# TASKS (placeholder implementation) 
@app.post("/tasks/start")
def start_task(
    upload_id: Optional[int] = Form(None),
    temp_id: Optional[str] = Form(None),
    me: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    if PERSIST_UPLOADS:
        if not upload_id:
            raise HTTPException(400, "Missing upload_id")
        u: Optional[Upload] = db.get(Upload, upload_id)
        if not u or u.user_id != me.id:
            raise HTTPException(404, "File not found")
        src_path = user_dir(me.id) / u.filename
    else:
        if not temp_id:
            raise HTTPException(400, "Missing temp_id")
        src_path = user_tmp_dir(me.id) / temp_id
        if not src_path.exists():
            raise HTTPException(404, "File not found")

    task_id = uuid.uuid4().hex
    t = Task(id=task_id, user_id=me.id, upload_id=upload_id or 0, status="queued", result_path=None)
    db.add(t); db.commit()

    # Call external detection script (YOLO etc.) to run real inference 
    result_name = f"result_{task_id}{src_path.suffix}"
    out_dir = user_dir(me.id) if PERSIST_UPLOADS else user_tmp_dir(me.id)
    out_path = out_dir / result_name
    rc, out = run_detector(src_path, out_path)

    if rc != 0 or not out_path.exists():
        t.status = "failed"
        db.commit()
        log_path = write_task_log(me.id, task_id, out or f"rc={rc}, no output")
        logging.error("Inference failed user=%s task=%s rc=%s log=%s", me.id, task_id, rc, log_path)

        if DEBUG_ERRORS:
            raise HTTPException(500, f"Inference failed (rc={rc}):\n{out}")
        raise HTTPException(500, f"Inference failed, please try again later (error code: {task_id})")

    logging.info("Inference succeeded user=%s task=%s result=%s", me.id, task_id, out_path.name)

    t.status = "completed"
    t.result_path = result_name
    db.commit()

    if not PERSIST_UPLOADS:
        try: src_path.unlink(missing_ok=True)
        except: pass

    return {"task_id": task_id, "status": "completed", "result_url": f"/results/{task_id}"}

@app.get("/tasks/{task_id}/status")
def task_status(task_id: str, me: User = Depends(get_current_user), db: Session = Depends(get_db)):
    t: Optional[Task] = db.get(Task, task_id)
    if not t or t.user_id != me.id:
        raise HTTPException(404, "Task not found")
    resp = {"task_id": t.id, "status": t.status}
    if t.status == "completed" and t.result_path:
        resp["result_url"] = f"/results/{t.id}"
    return resp

@app.get("/results/{task_id}")
def get_result(task_id: str, request: Request, db: Session = Depends(get_db)):
    me = auth_user_from_request(request, db)
    t: Optional[Task] = db.get(Task, task_id)
    if not t or t.user_id != me.id or t.status != "completed" or not t.result_path:
        raise HTTPException(404, "Result not available")
    base_dir = user_dir(me.id) if PERSIST_UPLOADS else user_tmp_dir(me.id)
    path = base_dir / t.result_path
    if not path.exists():
        raise HTTPException(404, "Result file not found")
    return FileResponse(path, filename=Path(t.result_path).name)
