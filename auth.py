# auth.py

import os
from dotenv import load_dotenv  # Import this

# Load environment variables from .env file
load_dotenv()

from fastapi import HTTPException, Depends
from fastapi.security import OAuth2PasswordBearer
from pydantic import EmailStr
from sqlalchemy.orm import Session
from passlib.context import CryptContext
from datetime import datetime, timedelta
import re
import uuid
from fastapi_mail import FastMail, MessageSchema, ConnectionConfig
from jose import JWTError, jwt
from typing import Optional

# Import get_db and the User model from your local files
from database import get_db
from models import User

# ---------------- Password & Lock Settings ----------------

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
MAX_ATTEMPTS = 5
LOCK_DURATION = timedelta(minutes=30)

# ---------------- JWT Settings ----------------
# CHANGED: Reading SECRET_KEY from environment variable
SECRET_KEY = os.getenv("SECRET_KEY") 
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 300

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

def hash_password(password: str):
    return pwd_context.hash(password)

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def validate_password(password: str, username: str):
    if len(password) < 8: return False, "Password too short"
    if username.lower() in password.lower(): return False, "Password too similar to username"
    if not re.search(r"[A-Z]", password): return False, "Password must contain uppercase"
    if not re.search(r"[a-z]", password): return False, "Password must contain lowercase"
    if not re.search(r"\d", password): return False, "Password must contain a number"
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password): return False, "Password must contain a special character"
    return True, ""

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

# ---------------- EMAIL SETUP ----------------
# CHANGED: Reading config from environment variables
conf = ConnectionConfig(
    MAIL_USERNAME=os.getenv("MAIL_USERNAME"),
    MAIL_PASSWORD=os.getenv("MAIL_PASSWORD"),
    MAIL_FROM=os.getenv("MAIL_FROM"),
    MAIL_PORT=int(os.getenv("MAIL_PORT")),
    MAIL_SERVER=os.getenv("MAIL_SERVER"),
    MAIL_STARTTLS=os.getenv("MAIL_STARTTLS") == "True", # Converts string "True" to boolean True
    MAIL_SSL_TLS=os.getenv("MAIL_SSL_TLS") == "True",     # Converts string "False" to boolean False
    USE_CREDENTIALS=True
)

async def send_reset_email(email, token):
    message = MessageSchema(
        subject="Password Reset",
        recipients=[email],
        body=f"Click here to reset your password: <a href='http://localhost:3000/reset-password/{token}'>Reset Password</a>",
        subtype="html"
    )
    fm = FastMail(conf)
    await fm.send_message(message)

# ---------------- Auth Functions ----------------

def register_user(db: Session, User, username: str, email: EmailStr, password: str):
    valid, msg = validate_password(password, username)
    if not valid: raise HTTPException(status_code=400, detail=msg)
    
    existing = db.query(User).filter((User.username==username)|(User.email==email)).first()
    if existing: raise HTTPException(status_code=400, detail="Username or email already exists")
    
    new_user = User(username=username, email=email, password_hash=hash_password(password))
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return {"message": "User registered successfully"}

def login_user(db: Session, User, LoginAttempt, username: str, password: str):
    user = db.query(User).filter(User.username==username).first()
    if not user: raise HTTPException(status_code=400, detail="User not found")
    
    if user.is_locked and user.locked_until and user.locked_until > datetime.utcnow():
        raise HTTPException(status_code=403, detail=f"Account locked until {user.locked_until}")
    elif user.is_locked and user.locked_until and user.locked_until <= datetime.utcnow():
        user.is_locked = False
        user.locked_until = None
        db.commit()
    
    if not verify_password(password, user.password_hash):
        attempt = LoginAttempt(user_id=user.id, success=False)
        db.add(attempt)
        db.commit()

        attempts = db.query(LoginAttempt).filter(
            LoginAttempt.user_id==user.id,
            LoginAttempt.success==False,
            LoginAttempt.attempt_time > datetime.utcnow() - timedelta(minutes=30)
        ).count()

        if attempts >= MAX_ATTEMPTS:
            user.is_locked = True
            user.locked_until = datetime.utcnow() + LOCK_DURATION
            db.commit()
            raise HTTPException(status_code=403, detail="Account locked for 30 minutes")

        raise HTTPException(status_code=400, detail="Incorrect password")
    
    attempt = LoginAttempt(user_id=user.id, success=True)
    db.add(attempt)
    db.commit()
    
    # Generate Token
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(data={"sub": user.username}, expires_delta=access_token_expires)
    
    return {"access_token": access_token, "token_type": "bearer", "message": "Login successful"}

async def forgot_password(db: Session, User, email: EmailStr):
    user = db.query(User).filter(User.email==email).first()
    if not user: raise HTTPException(status_code=400, detail="Email not found")
    
    token = str(uuid.uuid4())
    user.reset_token = token
    db.commit()
    await send_reset_email(user.email, token)
    return {"message": "Password reset email sent"}

def reset_password(db: Session, User, token: str, new_password: str):
    user = db.query(User).filter(User.reset_token==token).first()
    if not user: raise HTTPException(status_code=400, detail="Invalid token")
    
    valid, msg = validate_password(new_password, user.username)
    if not valid: raise HTTPException(status_code=400, detail=msg)
    
    user.password_hash = hash_password(new_password)
    user.reset_token = None
    db.commit()
    return {"message": "Password reset successful"}

# ---------------- FIXED get_current_user ----------------
def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=401, detail="Invalid authentication credentials")
    except JWTError:
        raise HTTPException(status_code=401, detail="Could not validate credentials")
    
    user = db.query(User).filter(User.username == username).first()
    if user is None:
        raise HTTPException(status_code=401, detail="User not found")
    return user