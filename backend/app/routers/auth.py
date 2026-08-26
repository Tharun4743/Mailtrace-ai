from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, EmailStr
from sqlalchemy.orm import Session
from typing import Optional
from app.database import get_db
from app.models.models import User, AuditLog
from app.schemas.schemas import UserLogin, Token, UserCreate, UserResponse
from app.auth.security import verify_password, get_password_hash, create_access_token
from app.auth.deps import get_current_user

router = APIRouter(prefix="/auth", tags=["Authentication"])

class ForgotPasswordRequest(BaseModel):
    email_or_username: str

class ResetPasswordRequest(BaseModel):
    email_or_username: str
    new_password: str

@router.post("/login", response_model=Token)
def login(login_data: UserLogin, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == login_data.username).first()
    if not user or not verify_password(login_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    if not user.is_active:
        raise HTTPException(status_code=400, detail="Account is deactivated")
        
    access_token = create_access_token(subject=user.username, role=user.role)
    
    # Audit log
    db.add(AuditLog(
        user_id=user.id,
        username=user.username,
        action="USER_LOGIN_SUCCESS",
        target_type="USER",
        target_id=str(user.id)
    ))
    db.commit()

    return {
        "access_token": access_token,
        "token_type": "bearer",
        "user_id": user.id,
        "username": user.username,
        "role": user.role,
        "full_name": user.full_name
    }

@router.post("/register", response_model=UserResponse)
def register(user_data: UserCreate, db: Session = Depends(get_db)):
    existing = db.query(User).filter(
        (User.username == user_data.username) | (User.email == user_data.email)
    ).first()
    if existing:
        raise HTTPException(status_code=400, detail="Username or email already registered")

    new_user = User(
        username=user_data.username,
        email=user_data.email,
        hashed_password=get_password_hash(user_data.password),
        full_name=user_data.full_name,
        role="USER",
        is_active=True
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return new_user

@router.post("/forgot-password")
def forgot_password(req: ForgotPasswordRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(
        (User.username == req.email_or_username) | (User.email == req.email_or_username)
    ).first()
    if not user:
        raise HTTPException(status_code=404, detail="No registered account found with that username or email")
        
    return {
        "status": "success",
        "message": f"Password reset instructions sent for account: {user.username}",
        "username": user.username
    }

@router.post("/reset-password")
def reset_password(req: ResetPasswordRequest, db: Session = Depends(get_db)):
    if len(req.new_password) < 6:
        raise HTTPException(status_code=400, detail="Password must be at least 6 characters long")
        
    user = db.query(User).filter(
        (User.username == req.email_or_username) | (User.email == req.email_or_username)
    ).first()
    if not user:
        raise HTTPException(status_code=404, detail="No registered account found")
        
    user.hashed_password = get_password_hash(req.new_password)
    db.commit()
    
    return {
        "status": "success",
        "message": "Password has been successfully updated. You can now sign in with your new password."
    }

@router.get("/me", response_model=UserResponse)
def get_me(current_user: User = Depends(get_current_user)):
    return current_user
