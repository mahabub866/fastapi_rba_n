from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from dotenv import load_dotenv
import os

from fastapi import status, HTTPException

load_dotenv()

url=os.getenv("db_url")

if url is None:
    raise HTTPException("DataBase url is not store .env file")

SQLALCHEMY_DATABASE_URL = url

engine = create_engine(
    SQLALCHEMY_DATABASE_URL, pool_size=200, max_overflow=0
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()

def get_db():
    db = SessionLocal() 
    try:
        yield db
    finally:
        db.close()

