from datetime import datetime


from fastapi import APIRouter, Depends, status, HTTPException


from sqlalchemy.orm import Session
from sqlalchemy import and_, or_, asc
from globalfun import validation_user_management
from fastapi.encoders import jsonable_encoder
from database import get_db
from models import RoleModel,RoleUserModel,BlockModel
import uuid
from schema import RoleModelCreate,RoleStatusUpdate,RoleUpdate
from globalfun import flatten_list_of_dicts
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
    mak=Authorize.get_raw_jwt()
    Authorize.jwt_required()
    user_id=Authorize.get_jwt_subject()
    valid=validation_user_management(user_id, db,mak['jti'])
    if valid==True:
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
            "message":"New Role Created",
            "create_at":str(create_at),
            "admin":str(user_id)
        }

        new_role = RoleModel(uid=uId,name=request.name,active=request.active,role=roles,logs=log,create_at= create_at)
        db.add(new_role)
        db.commit()
        db.refresh(new_role)

        return {'status_code': status.HTTP_201_CREATED, 'success': True, 'message': "Role Create Succesfully"}
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED, detail="Something happened")
               

@role_router.get('/all', status_code=status.HTTP_200_OK)
async def create_user( db: Session = Depends(get_db),Authorize:AuthJWT=Depends()):
    mak=Authorize.get_raw_jwt()
    Authorize.jwt_required()
    user_id=Authorize.get_jwt_subject()
    valid=validation_user_management(user_id, db,mak['jti'])
    if valid==True:
                # data=db.query(RoleUserModel).options(load_only(*['name','user_id',"uid",'id','email','mobile_number','role_id','super_admin','active',"logs","create_at"])).all()
        data=db.query(RoleModel).all()
        result = [{"name": item.name,"uid":item.uid,'id':item.id,'super_admin':item.super_admin,'active':item.active,"logs":item.logs,"create_at":item.create_at} for item in data]
        
        return {'status_code': status.HTTP_201_CREATED, 'success': True, 'data': result}
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED, detail="Something happened")


@role_router.put('/update/status', status_code=status.HTTP_201_CREATED)
async def create_user( request:RoleStatusUpdate,db: Session = Depends(get_db),Authorize:AuthJWT=Depends()):
    mak=Authorize.get_raw_jwt()
    Authorize.jwt_required()
    user_id=Authorize.get_jwt_subject()
    valid=validation_user_management(user_id, db,mak['jti'])
    if valid==True:
        create_at=datetime.now()
        user=db.query(RoleModel).filter(RoleModel.uid==request.uid).first()
        
        if user:
            if db.query(RoleModel).filter(and_(RoleModel.uid==request.uid,RoleModel.super_admin==True)).first():
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Super Admin Role is not editable")
            new_logs={}
            if request.active==True:
                new_logs={
                    "admin": str(user_id),
                    "message": "role is actived",
                    "create_at": str(create_at)
                }
            else:
                    new_logs={
                    "admin": str(user_id),
                    "message": "role is deactived",
                    "create_at": str(create_at)
                }

            logs = []
            logs.append(user.logs)
            logs.append(new_logs)
            logs_data=flatten_list_of_dicts(logs)
            db.query(RoleModel).filter(RoleModel.uid==request.uid).update({'active': request.active,'logs':logs_data})
            db.commit()
            return {'status_code': status.HTTP_201_CREATED, 'success': True,"message":"Role Status is Update" }
        raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED, detail="Something happened")
    

@role_router.put('/update', status_code=status.HTTP_201_CREATED)
async def create_user( request:RoleUpdate,db: Session = Depends(get_db),Authorize:AuthJWT=Depends()):
    mak=Authorize.get_raw_jwt()
    Authorize.jwt_required()
    user_id=Authorize.get_jwt_subject()
    valid=validation_user_management(user_id, db,mak['jti'])
    if valid==True:
        create_at=datetime.now()
        user=db.query(RoleModel).filter(RoleModel.uid==request.uid).first()
        
        if user:
            if db.query(RoleModel).filter(and_(RoleModel.uid==request.uid,RoleModel.super_admin==True)).first():
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Super Admin is not editable")
            new_logs={
                "admin": str(user_id),
                "message": "role updated",
                "create_at": str(create_at)
            }
            roles={
        
            "tv_app_management": request.tv_app_management,
            "user_management": request.user_management,
            "end_tv_app_user_management": request.end_tv_app_user_management,
            "app_management": request.app_management,
            }
            logs = []
            logs.append(user.logs)
            logs.append(new_logs)
            logs_data=flatten_list_of_dicts(logs)
            db.query(RoleModel).filter(RoleModel.uid==request.uid).update({'active': request.active,'name':request.name,'role':roles,'logs':logs_data})
            db.commit()
            return {'status_code': status.HTTP_201_CREATED, 'success': True,"message":"Role is Update" }
        raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
                
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED, detail="Something happened")
    

@role_router.delete('/delete/{delete_id}', status_code=status.HTTP_201_CREATED)
async def create_user(delete_id:str,db: Session = Depends(get_db),Authorize:AuthJWT=Depends()):
    mak=Authorize.get_raw_jwt()
    Authorize.jwt_required()
    user_id=Authorize.get_jwt_subject()
    valid=validation_user_management(user_id, db,mak['jti'])
    if valid==True:
        user=db.query(RoleModel).filter(RoleModel.uid==delete_id).first()
        
        if user:
            if db.query(RoleModel).filter(and_(RoleModel.uid==delete_id,RoleModel.super_admin==True)).first():
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Super Admin is not Deletable")
            
            db.query(RoleModel).filter(RoleModel.uid==delete_id).delete()
            db.commit()
            return {'status_code': status.HTTP_201_CREATED, 'success': True,"message":"Role is Deleted" }
        raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
                
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED, detail="Something happened")
    