from datetime import datetime


from fastapi import APIRouter, Depends, status, HTTPException


from sqlalchemy.orm import Session
from sqlalchemy import and_, or_, asc

from fastapi.encoders import jsonable_encoder
from database import get_db
from models import RoleModel
import uuid
from schema import RoleModelCreate

from fastapi_jwt_auth import AuthJWT

uId=str(uuid.uuid4())

role_router = APIRouter(
    prefix='/margaret/role',
    tags=['Role']
)

@role_router.get('/create/super-admin', status_code=status.HTTP_201_CREATED)
async def create_user( db: Session = Depends(get_db)):
   
    create_at=datetime.now()

    is_exixt=  db.query(RoleModel).first()
    if is_exixt:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Super Admin Role Already exist")
    roles={
     
        "tv_app_management": 'a',
        "user_management":'a',
        "end_tv_app_user_management": 'a',
        "app_management": 'a',
    }
    log={
         "message":"First Role Created",
        "create_at":str(create_at),
        "admin":"11223344"
    }
    new_role = RoleModel(uid="11223344",name="Super Admin",super_admin=True,active=True,role=roles,logs=log,create_at= create_at)
    db.add(new_role)
    db.commit()
    db.refresh(new_role)

    return {'status_code': status.HTTP_201_CREATED, 'success': True, 'message': "1st Role Create Succesfully"}


@role_router.post('/create', status_code=status.HTTP_201_CREATED)
async def create_user(request: RoleModelCreate, db: Session = Depends(get_db),Authorize:AuthJWT=Depends()):
    print(Authorize)
    create_at=datetime.now()
    is_exixt=  db.query(RoleModel).filter(RoleModel.name ==request.name).first()
    if is_exixt:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Name Already exist")
    
    roles={
     
        "tv_app_management": request.tv_app_management,
        "user_management": request.user_management,
        "end_tv_app_user_management": request.end_tv_app_user_management,
        "app_management": request.app_management,
    }
    log={
         "message":"Role Created",
        "create_at":str(create_at),
        "admin":"223350"
    }

    new_role = RoleModel(uid=uId,name=request.name,super_admin= request.super_admin,active=request.active,role=roles,logs=log,create_at= create_at)
    db.add(new_role)
    db.commit()
    db.refresh(new_role)

    return {'status_code': status.HTTP_201_CREATED, 'success': True, 'message': "Role Create Succesfully"}

