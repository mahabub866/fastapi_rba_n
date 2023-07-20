from datetime import datetime, timezone,timedelta
from email.policy import default

from sqlalchemy import Column, Integer, String, ForeignKey, DateTime, Boolean,ARRAY
from sqlalchemy.orm import relationship
from sqlalchemy_utils.types import ChoiceType
from database import Base
from sqlalchemy.dialects.mysql import JSON
import uuid


class RoleUserModel(Base):
    __tablename__="role_users"

    id = Column(Integer, primary_key=True)
    uid = Column(String(255), unique=True, nullable=False)
    name = Column(String(80), nullable=False)
    user_id = Column(String(80), unique=True, nullable=False)
    password  = Column(String(255), nullable=False)
    email  = Column(String(80), unique=True, nullable=True)
    mobile_number = Column(String(11), unique=True, nullable=False)
    token  = Column(String(500), unique=True, nullable=True)
    role_id  = Column(String(255), nullable=True)
    super_admin = Column(Boolean, default=False)
    active = Column(Boolean, default=True)
    jti = Column(String(255), nullable=True)
    info1 = Column(String(255), nullable=True)
    info2 = Column(String(255), nullable=True)
    extra_info = Column(JSON)
    logs = Column(JSON)
    create_at = Column(DateTime, nullable=True, default=datetime.now(timezone.utc))


    def __repr__(self):
        return f'<RoleUserModel {self.name}'