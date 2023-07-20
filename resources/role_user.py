from datetime import datetime
from fastapi import APIRouter, Depends, status, HTTPException

from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy.orm import Session
from sqlalchemy import and_, or_, asc


from fastapi.encoders import jsonable_encoder
from database import get_db
from models import RoleUserModel,RoleModel,BlockModel
import uuid
from schema import RoleUserCreate,LoginModel
from globalfun import authfunc,decode_token,authfuncjti
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
    new_role = RoleUserModel(uid=uId,name="Mahabobur Rahman",email="mahaub@gmail.com",user_id="1105003",password=generate_password_hash('12345678'),super_admin= True,mobile_number="01521216116",role_id="11223344",logs=log,create_at=create_at)
    db.add(new_role)
    db.commit()
    db.refresh(new_role)
    return {'status_code': status.HTTP_201_CREATED, 'success': True, 'message': "1st User Create Succesfully"}


@role_user_router.post('/login',status_code=status.HTTP_200_OK)
async def login(request:LoginModel,db: Session = Depends(get_db),Authorize:AuthJWT=Depends()):
    db_user=db.query(RoleUserModel).filter(RoleUserModel.user_id==request.user_id).first()

    if db_user is None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,detail="Invalid User ID")

    db_role=db.query(RoleModel).filter(RoleModel.uid==db_user.role_id).first()
    if db_role is None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,detail="Invalid Role Id")

    
    if db_user and check_password_hash(db_user.password,request.password):
        access_token=Authorize.create_access_token(subject=request.user_id)
        refresh_token=Authorize.create_refresh_token(subject=request.user_id)
        payload=decode_token(access_token,db)
        # print(payload[0])
        # print(payload[3])
        data={}
        if db_user.token is None:
            db.query(RoleUserModel).filter(and_(RoleUserModel.user_id==request.user_id,RoleUserModel.user_id==db_user.user_id)).update({"token":access_token,"jti":str(payload[3])})
            db.commit()
            token_value =db.query(RoleUserModel).filter(and_(RoleUserModel.token!=None,RoleUserModel.user_id==request.user_id)).first()
            role=db.query(RoleModel).filter(RoleModel.uid==token_value.role_id).first()
            data = {"access_token": token_value.token,"role":role.role,"name":db_user.name,"user_id":db_user.user_id,"refresh_token":refresh_token}
        
        else:
            payloads=decode_token(db_user.token,db)
           
            block_token=BlockModel(block_id=str(uuid.uuid4()),token=db_user.token,user_id=payloads['sub'],jti=payloads['jti'],create_at=datetime.utcnow())
            db.add(block_token)
            db.commit()
            db.refresh(block_token)
           
           
            maks=db.query(RoleUserModel).filter(and_(RoleUserModel.token!=None,RoleUserModel.user_id==request.user_id)).first()
            if maks:
                print('c3')
                db.query(RoleUserModel).filter(RoleUserModel.user_id==request.user_id).update({"token":access_token,"jti":payload['jti']})
                db.commit()
                token_value =db.query(RoleUserModel).filter(and_(RoleUserModel.token!=None,RoleUserModel.user_id==request.user_id)).first()
                role=db.query(RoleModel).filter(RoleModel.uid==token_value.role_id).first()
                data = {"access_token": token_value.token,"role":role.role,"name":db_user.name,"user_id":db_user.user_id,"refresh_token":refresh_token}

        return jsonable_encoder(data)
    
    raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,detail="Invalid Password")


@role_user_router.post('/create', status_code=status.HTTP_201_CREATED)
async def create_user(request: RoleUserCreate, db: Session = Depends(get_db),Authorize:AuthJWT=Depends()):
    
    try:
        ss=Authorize.jwt_required()
        print(ss)
        mak=Authorize.get_jwt_subject()
        jak=Authorize.get_raw_jwt()
        print(jak)
        print(mak)
        
        print(Authorize.jwt_required())

    except Exception as e:
        print(e)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid Token")
    
    # data=  db.query(RoleUserModel).filter(and_(RoleUserModel.user_id ==user_id,RoleUserModel.jti==jti)).first()
    # print(data)
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

    new_role = RoleUserModel(uid=uId,name=request.name,email=request.email,user_id=request.user_id,password=generate_password_hash(request.password),super_admin= True,mobile_number=request.mobile_number,role_id=request.role,active=request.active,logs=log,create_at= create_at)
    # db.add(new_role)
    # db.commit()
    # db.refresh(new_role)

    return {'status_code': status.HTTP_201_CREATED, 'success': True, 'message': "User Create Succesfully"}

