from datetime import datetime
from enum import Enum
from pydantic import BaseModel,Field,validator
from typing import  Optional,List
from datetime import timedelta


class RoleModelCreate(BaseModel):
    name: str
    active: Optional[bool] = True
    user_management: Optional[str] = 'a'
    tv_app_management: Optional[str] = 'a'
    app_management: Optional[str] = 'a'
    end_tv_app_user_management: Optional[str] = 'a'

    class Config:
        extra = "forbid"


class RoleUpdate(BaseModel):
    uid: str
    name: str
    active: bool
    user_management: str 
    tv_app_management: str 
    app_management: str 
    end_tv_app_user_management: str 

    class Config:
        extra = "forbid"

class RoleStatusUpdate(BaseModel):
    uid: str
    active:bool
   

    class Config:
        extra = "forbid"

