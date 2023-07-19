from datetime import datetime
from enum import Enum
from pydantic import BaseModel,Field,validator
from typing import  Optional,List
from datetime import timedelta


class RoleModelCreate(BaseModel):
    name: str
    super_admin: Optional[bool] = True
    active: Optional[bool] = True
    user_management: Optional[str] = 'i'
    tv_app_management: Optional[str] = 'i'
    app_management: Optional[str] = 'i'
    end_tv_app_user_management: Optional[str] = 'i'

    class Config:
        extra = "forbid"


class RoleModelUpdate(BaseModel):
    uuid: str
    name: Optional[str]
    active: Optional[bool]
    user_management: Optional[str] = 'i'
    tv_app_management: Optional[str] = 'i'
    app_management: Optional[str] = 'i'
    end_tv_app_user_management: Optional[str] = 'i'
    info1: Optional[str]
    info2: Optional[str]
    extra_info: Optional[dict]

    class Config:
        extra = "forbid"

