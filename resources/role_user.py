from datetime import datetime
from fastapi import APIRouter, Depends, status, HTTPException

from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy.orm import Session
from sqlalchemy import and_, or_, asc

from fastapi.encoders import jsonable_encoder
from database import get_db
from models import RoleUserModel
import uuid
from schema import RoleUserCreate,LoginModel
from globalfun import authfunc,get_data_from_jwt_token
from fastapi_jwt_auth import AuthJWT

uId=str(uuid.uuid4())
role_user_router = APIRouter(
    prefix='/margaret/role-user',
    tags=['RoleUser']
)

@role_user_router.get('/create/super-user', status_code=status.HTTP_201_CREATED)
async def create_user(db: Session = Depends(get_db)):
    create_at=datetime.now()
    is_exixt=  db.query(RoleUserModel).first()
    if is_exixt:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Super Admin User is Already Created")
    log={
         "message":"User Created",
        "create_at":str(create_at),
        "admin":"11223344"
    }
    new_role = RoleUserModel(uid=uId,name="Mahabobur Rahman",email="mahaub@gmail.com",user_id="1105003",password=generate_password_hash('12345678'),super_admin= True,mobile_number="01521216116",role_name="11223344",logs=log,create_at=create_at)
    db.add(new_role)
    db.commit()
    db.refresh(new_role)
    return {'status_code': status.HTTP_201_CREATED, 'success': True, 'message': "1st User Create Succesfully"}


@role_user_router.post('/login',status_code=status.HTTP_200_OK)
async def login(request:LoginModel,db: Session = Depends(get_db),Authorize:AuthJWT=Depends()):
    db_user=db.query(RoleUserModel).filter(RoleUserModel.user_id==request.user_id).first()

    if db_user is None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,detail="Invalid User ID")
    
    if db_user and check_password_hash(db_user.password,request.password):
        access_token=Authorize.create_access_token(subject=request.user_id)
        refresh_token=Authorize.create_refresh_token(subject=request.user_id)
        decode_jti=decode_token(access_token)
        response={
            "access":access_token,
            "token_type":'Bearer',
            "refresh":refresh_token,
            "name":db_user.name,
            "mobile_number":db_user.mobile_number,
            "user_id":db_user.user_id,
            "super_admin":db_user.super_admin,
            "active":db_user.active
        }
        
        

        if ((db_user.active is not True) and (db_user.super_admin is not True)):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,detail="Staff is Not Active")

        if (db_user.active is not True):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,detail="User is Not Active")
            
        if db_user:
            print(access_token)
            db.query(RoleUserModel).filter(RoleUserModel.user_id==db_user.user_id).update({'token':access_token})
            db.commit()
        return jsonable_encoder(response)
    
    raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,detail="Invalid Password")


@role_user_router.post('/create', status_code=status.HTTP_201_CREATED)
async def create_user(request: RoleUserCreate, db: Session = Depends(get_db),Authorize:AuthJWT=Depends()):
    data=  db.query(RoleUserModel).filter(RoleUserModel.user_id ==request.user_id).first()
    if data:
        get_data_from_jwt_token(data.token,Authorize)
    
    print(Authorize)
    decoded_payload = Authorize.jwt_manager.jwt_payload
    jti_value = decoded_payload.get("jti")
    print(jti_value)
    authfunc(Authorize)
    username = Authorize.get_jwt_subject()
    print(username)
    create_at=datetime.now()
    is_exixt_id=  db.query(RoleUserModel).filter(RoleUserModel.user_id ==request.user_id).first()
    is_exixt_email=  db.query(RoleUserModel).filter(RoleUserModel.email ==request.email).first()
    is_exixt_mobile=  db.query(RoleUserModel).filter(RoleUserModel.mobile_number ==request.mobile_number).first()
    

    if is_exixt_id:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="User Id Already exist")
    if is_exixt_email:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email Already exist")
    if is_exixt_mobile:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Mobile Number Already exist")
    
    log={
         "message":"User Created",
        "create_at":str(create_at),
        "admin":"223350"
    }

    new_role = RoleUserModel(uid=uId,name=request.name,email=request.email,user_id=request.user_id,password=generate_password_hash(request.password),super_admin= True,mobile_number=request.mobile_number,role_name=request.role,active=request.active,logs=log,create_at= create_at)
    # db.add(new_role)
    # db.commit()
    # db.refresh(new_role)

    return {'status_code': status.HTTP_201_CREATED, 'success': True, 'message': "User Create Succesfully"}

