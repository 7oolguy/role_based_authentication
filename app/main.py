from app.config.database import Base, engine
from typing import Union
from fastapi import FastAPI
from app.core.security import router
from app.router.create import c
from app.router.get import g
from app.router.edit import e
from app.router.delete import d
from app.router.auth import auth

app = FastAPI()

# Function to create all tables in the database
def create_db_tables():
    Base.metadata.create_all(bind=engine)

create_db_tables()

@app.get("/health")
async def health():
    return {"message": "ok!"}

app.include_router(c)
app.include_router(d)
app.include_router(e)
app.include_router(g)
app.include_router(auth)
app.include_router(router)
