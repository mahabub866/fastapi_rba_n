from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

# SQLALCHEMY_DATABASE_URL = "sqlite:///./qmatic_dyb.db"
SQLALCHEMY_DATABASE_URL = "mysql+mysqlconnector://root:password@localhost:3306/rba"

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

