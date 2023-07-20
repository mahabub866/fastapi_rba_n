
from datetime import datetime, timezone,timedelta
from email.policy import default

from sqlalchemy import Column, Integer, String, ForeignKey, DateTime, Boolean,ARRAY
from sqlalchemy.orm import relationship
from sqlalchemy_utils.types import ChoiceType
from database import Base
from sqlalchemy.dialects.mysql import JSON
import uuid


class BlockModel(Base):
    __tablename__="blocks"

    id = Column(Integer, primary_key=True)
    block_id = Column(String(255), unique=True, nullable=False)
    token = Column(String(500), unique=True, nullable=False)
    user_id = Column(String(80), nullable=False)
    jti = Column(String(80), unique=True, nullable=False)
    role = Column(JSON)
    info1 = Column(String(255), nullable=True)
    info2 = Column(String(255), nullable=True)
    extra_info = Column(JSON)
    logs = Column(JSON)
    create_at = Column(DateTime, nullable=True, default=datetime.now(timezone.utc))


    def __repr__(self):
        return f'<BlockModel {self.jti}'