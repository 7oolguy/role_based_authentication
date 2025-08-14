from fastapi import APIRouter, HTTPException, status, Depends
from pydantic import BaseModel
from sqlalchemy.orm import Session
from typing import List
from app.model.user import User
from app.core.database import get_db

class UserDataResponse(BaseModel):
    uuid: str
    user_identification: str

    class Config:
        orm_mode = True

g = APIRouter()

@g.get("/get_users", response_model=List[UserDataResponse])
async def get_all_users(db: Session = Depends(get_db)):
    return db.query(User).all()

@g.get("/get_user/{user_uuid}", response_model=UserDataResponse)
async def get_user_by_uuid(user_uuid: str, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.uuid == user_uuid).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    return user
