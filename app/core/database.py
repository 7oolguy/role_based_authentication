from app.config.database import Base, Session, SessionLocal

def get_db():
    db=SessionLocal()
    try:
        yield db
    finally:
        db.close()
