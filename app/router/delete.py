from fastapi import APIRouter, HTTPException, status, Depends
from sqlalchemy.orm import Session
from app.model.user import User
from app.core.database import get_db

d = APIRouter()

@d.delete("/delete_user/{user_uuid}", status_code=status.HTTP_200_OK)
async def delete_user(user_uuid: str, db: Session = Depends(get_db)):
    # Find the user
    user = db.query(User).filter(User.uuid == user_uuid).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )

    # Delete and commit
    db.delete(user)
    db.commit()

    return {"message": f"User {user_uuid} deleted successfully"}
