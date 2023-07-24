from datetime import datetime
from enum import Enum
from pydantic import BaseModel,Field,validator
from typing import  Optional,List
from datetime import timedelta

class RoleUserCreate(BaseModel):
    name: str
    user_id: str
    mobile_number: str
    email: str
    password: str
    role: str
    active: bool = None

    class Config:
        orm_mode = True
    class Config:
        extra = "forbid"

class LoginModel(BaseModel):
    user_id:str
    password:str

    class Config:
        extra = "forbid"


class RoleUserUpdate(BaseModel):
    uid: str
    name: str
    active: bool
    role:str
    email:str
    mobile_number:str

    class Config:
        extra = "forbid"

class RoleUserStatusUpdate(BaseModel):
    uid: str
    active:bool

    class Config:
        extra = "forbid"


class AdminSelfUserChangePasswordSchema(BaseModel):
    uid: str
    new_password: str
    old_password: str

    class Config:
        extra = "forbid"


class AdminUserChangePasswordSchema(BaseModel):
    uid: str
    new_password: str

    class Config:
        extra = "forbid"