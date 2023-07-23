from datetime import datetime
from fastapi import APIRouter, Depends, status, HTTPException

from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy.orm import Session
from sqlalchemy import and_, or_, asc
import jwt
from fastapi_jwt_auth.exceptions import InvalidHeaderError
from fastapi.encoders import jsonable_encoder
from database import get_db
from models import RoleUserModel,RoleModel,BlockModel
import uuid
from schema import RoleUserCreate,LoginModel,RoleUserStatusUpdate,RoleUserUpdate
from globalfun import decode_token,authfuncjti,flatten_list_of_dicts
from fastapi_jwt_auth import AuthJWT
from sqlalchemy.orm import Session, load_only

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
       
       
        # print(db_user.token)
        data={}
        if db_user.token is None:
            payload=decode_token(access_token,db)
            print(payload,'payloaddddd')
            db.query(RoleUserModel).filter(and_(RoleUserModel.user_id==request.user_id,RoleUserModel.user_id==db_user.user_id)).update({"token":access_token,"jti":payload['jti']})
            db.commit()
            token_value =db.query(RoleUserModel).filter(and_(RoleUserModel.token!=None,RoleUserModel.user_id==request.user_id)).first()
            role=db.query(RoleModel).filter(RoleModel.uid==token_value.role_id).first()
            data = {"access_token": token_value.token,"role":role.role,"name":db_user.name,"user_id":db_user.user_id,"refresh_token":refresh_token}
            
        
        else:
            payloads=decode_token(db_user.token,db)
            print(payloads,'payloads')
            block_token=BlockModel(block_id=str(uuid.uuid4()),token=db_user.token,user_id=payloads['sub'],jti=payloads['jti'],create_at=datetime.utcnow())
            db.add(block_token)
            db.commit()
            db.refresh(block_token)
           
           
            maks=db.query(RoleUserModel).filter(and_(RoleUserModel.token!=None,RoleUserModel.user_id==request.user_id)).first()
            if maks:
                print('c3')
                payload=decode_token(access_token,db)
                db.query(RoleUserModel).filter(RoleUserModel.user_id==request.user_id).update({"token":access_token,"jti":payload['jti']})
                db.commit()
                token_value =db.query(RoleUserModel).filter(and_(RoleUserModel.token!=None,RoleUserModel.user_id==request.user_id)).first()
                role=db.query(RoleModel).filter(RoleModel.uid==token_value.role_id).first()
                data = {"access_token": token_value.token,"role":role.role,"name":db_user.name,"user_id":db_user.user_id,"refresh_token":refresh_token}

        return jsonable_encoder(data)
        # raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,detail="Invalid Password")
    
    raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,detail="Invalid Password")


@role_user_router.post('/create', status_code=status.HTTP_201_CREATED)
async def create_user(request: RoleUserCreate, db: Session = Depends(get_db),Authorize:AuthJWT=Depends()):
    mak=Authorize.get_raw_jwt()
    try:
        Authorize.jwt_required()
       
        block_token=db.query(BlockModel).filter(BlockModel.jti==mak['jti']).first()
        if block_token:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token is already block")
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid Token")
    user_id=Authorize.get_jwt_subject()

    data=  db.query(RoleUserModel).filter(and_(RoleUserModel.user_id ==user_id,RoleUserModel.jti==mak['jti'])).first()
    
    if data is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="User Not Found")
    
    data2=  db.query(RoleModel).filter(RoleModel.uid ==data.role_id).first()

    if data2 is None:
        raise HTTPException(
           status_code=status.HTTP_404_NOT_FOUND, detail="Role Not Found")
    if data2.active==True:
        if data2.role['user_management']=='a':
            if data.active==True:
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
                    "message":"New User Created",
                    "create_at":str(create_at),
                    "admin":str(user_id)
                }

                new_role = RoleUserModel(uid=uId,name=request.name,email=request.email,user_id=request.user_id,password=generate_password_hash(request.password),super_admin= True,mobile_number=request.mobile_number,role_id=request.role,active=request.active,logs=log,create_at= create_at)
                db.add(new_role)
                db.commit()
                db.refresh(new_role)
                return {'status_code': status.HTTP_201_CREATED, 'success': True, 'message': "User Create Succesfully"}
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail="User is not active")
            
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="This Role is not permitted for you")
    raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Role is not active")


@role_user_router.get('/all', status_code=status.HTTP_200_OK)
async def create_user( db: Session = Depends(get_db),Authorize:AuthJWT=Depends()):
    mak=Authorize.get_raw_jwt()
    try:
        Authorize.jwt_required()
       
        block_token=db.query(BlockModel).filter(BlockModel.jti==mak['jti']).first()
        if block_token:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token is already block")
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid Token")
    user_id=Authorize.get_jwt_subject()

    data=  db.query(RoleUserModel).filter(and_(RoleUserModel.user_id ==user_id,RoleUserModel.jti==mak['jti'])).first()
    
    if data is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid Token")
    
    data2=  db.query(RoleModel).filter(RoleModel.uid ==data.role_id).first()

    if data2 is None:
        raise HTTPException(
           status_code=status.HTTP_404_NOT_FOUND, detail="Role Not Found")
    if data2.active==True:
        if data2.role['user_management']=='a':
            if data.active==True:
                # data=db.query(RoleUserModel).options(load_only(*['name','user_id',"uid",'id','email','mobile_number','role_id','super_admin','active',"logs","create_at"])).all()
                data=db.query(RoleUserModel).all()
                result = [{"name": item.name, "user_id": item.user_id,"uid":item.uid,'id':item.id,'email':item.email,'mobile_number':item.mobile_number,'role_id':item.role_id,'super_admin':item.super_admin,'active':item.active,"logs":item.logs,"create_at":item.create_at} for item in data]
                
                return {'status_code': status.HTTP_201_CREATED, 'success': True, 'data': result}
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail="User is not active")
            
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="This Role is not permitted for you")
    raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Role is not active")


@role_user_router.put('/update/status', status_code=status.HTTP_201_CREATED)
async def create_user( request:RoleUserStatusUpdate,db: Session = Depends(get_db),Authorize:AuthJWT=Depends()):
    mak=Authorize.get_raw_jwt()
    try:
        Authorize.jwt_required()
       
        block_token=db.query(BlockModel).filter(BlockModel.jti==mak['jti']).first()
        if block_token:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token is already block")
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid Token")
    user_id=Authorize.get_jwt_subject()

    data=  db.query(RoleUserModel).filter(and_(RoleUserModel.user_id ==user_id,RoleUserModel.jti==mak['jti'])).first()
    
    if data is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="User Not Found")
    
    data2=  db.query(RoleModel).filter(RoleModel.uid ==data.role_id).first()

    if data2 is None:
        raise HTTPException(
           status_code=status.HTTP_404_NOT_FOUND, detail="Role Not Found")
    if data2.active==True:
        if data2.role['user_management']=='a':
            if data.active==True:
                create_at=datetime.now()
                user=db.query(RoleUserModel).filter(RoleUserModel.uid==request.uid).first()
               
                if user:
                    if db.query(RoleUserModel).filter(and_(RoleUserModel.uid==request.uid,RoleUserModel.super_admin==True)).first():
                        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Super Admin is not editable")
                    new_logs={}
                    if request.active==True:
                        new_logs={
                            "admin": str(user_id),
                            "message": "user is actived",
                            "create_at": str(create_at)
                        }
                    else:
                         new_logs={
                            "admin": str(user_id),
                            "message": "user is deactived",
                            "create_at": str(create_at)
                        }

                    logs = []
                    mak=flatten_list_of_dicts(user.logs)
                    logs.append(mak)
                    logs.append(new_logs)
                    one_array_logs=[]
                    for item in logs:
                        if isinstance(item, list):
                            one_array_logs.extend(item)
                        elif isinstance(item, dict):
                            one_array_logs.append(item)
                    db.query(RoleUserModel).filter(RoleUserModel.uid==request.uid).update({'active': request.active,'logs':one_array_logs})
                    db.commit()
                    return {'status_code': status.HTTP_201_CREATED, 'success': True,"message":"User Status is Update" }
                
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND, detail="User Not Found")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail="User is not active")
            
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="This Role is not permitted for you")
    raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Role is not active")
    

@role_user_router.put('/update', status_code=status.HTTP_201_CREATED)
async def create_user( request:RoleUserUpdate,db: Session = Depends(get_db),Authorize:AuthJWT=Depends()):
    mak=Authorize.get_raw_jwt()
    try:
        Authorize.jwt_required()
       
        block_token=db.query(BlockModel).filter(BlockModel.jti==mak['jti']).first()
        if block_token:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token is already block")
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid Token")
    user_id=Authorize.get_jwt_subject()

    data=  db.query(RoleUserModel).filter(and_(RoleUserModel.user_id ==user_id,RoleUserModel.jti==mak['jti'])).first()
    
    if data is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="User Not Found")
    
    data2=  db.query(RoleModel).filter(RoleModel.uid ==data.role_id).first()

    if data2 is None:
        raise HTTPException(
           status_code=status.HTTP_404_NOT_FOUND, detail="Role Not Found")
    if data2.active==True:
        if data2.role['user_management']=='a':
            if data.active==True:
                create_at=datetime.now()
                user=db.query(RoleUserModel).filter(RoleUserModel.uid==request.uid).first()
               
                if user:
                    if db.query(RoleUserModel).filter(and_(RoleUserModel.uid==request.uid,RoleUserModel.super_admin==True)).first():
                        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Super Admin is not editable")
                    
                    # if db.query(RoleUserModel).filter(RoleUserModel.email ==request.email).first():
                    #     raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email is Already exist")
                    # if db.query(RoleUserModel).filter(RoleUserModel.mobile_number ==request.mobile_number).first():
                    #     raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Mobile Number is Already exist")
                    new_logs={
                        "admin": str(user_id),
                        "message": "user updated",
                        "create_at": str(create_at)
                    }
                    logs = []
                    mak=flatten_list_of_dicts(user.logs)
                    logs.append(mak)
                    logs.append(new_logs)
                    one_array_logs=[]
                    for item in logs:
                        if isinstance(item, list):
                            one_array_logs.extend(item)
                        elif isinstance(item, dict):
                            one_array_logs.append(item)
                    db.query(RoleUserModel).filter(RoleUserModel.uid==request.uid).update({'active': request.active,'name':request.name,'mobile_number':request.mobile_number,'email':request.email,'logs':one_array_logs})
                    db.commit()
                    return {'status_code': status.HTTP_201_CREATED, 'success': True,"message":"User Status is Update" }
                
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND, detail="User Not Found")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail="User is not active")
            
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="This Role is not permitted for you")
    raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Role is not active")
    

@role_user_router.delete('/delete/{delete_id}', status_code=status.HTTP_201_CREATED)
async def create_user(delete_id:str,db: Session = Depends(get_db),Authorize:AuthJWT=Depends()):
    mak=Authorize.get_raw_jwt()
    try:
        Authorize.jwt_required()
       
        block_token=db.query(BlockModel).filter(BlockModel.jti==mak['jti']).first()
        if block_token:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token is already block")
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid Token")
    user_id=Authorize.get_jwt_subject()

    data=  db.query(RoleUserModel).filter(and_(RoleUserModel.user_id ==user_id,RoleUserModel.jti==mak['jti'])).first()
    
    if data is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="User Not Found")
    
    data2=  db.query(RoleModel).filter(RoleModel.uid ==data.role_id).first()

    if data2 is None:
        raise HTTPException(
           status_code=status.HTTP_404_NOT_FOUND, detail="Role Not Found")
    if data2.active==True:
        if data2.role['user_management']=='a':
            if data.active==True:
                user=db.query(RoleUserModel).filter(RoleUserModel.user_id==delete_id).first()
               
                if user:
                    if db.query(RoleUserModel).filter(and_(RoleUserModel.user_id==delete_id,RoleUserModel.super_admin==True)).first():
                        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Super Admin is not Deletable")
                    
                    db.query(RoleUserModel).filter(RoleUserModel.user_id==delete_id).delete()
                    db.commit()
                    return {'status_code': status.HTTP_201_CREATED, 'success': True,"message":"User is Deleted" }
                
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND, detail="User Not Found")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail="User is not active")
            
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="This Role is not permitted for you")
    raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Role is not active")
    


@role_user_router.get('/role-helper', status_code=status.HTTP_200_OK)
async def create_user( db: Session = Depends(get_db),Authorize:AuthJWT=Depends()):
    mak=Authorize.get_raw_jwt()
    try:
        Authorize.jwt_required()
       
        block_token=db.query(BlockModel).filter(BlockModel.jti==mak['jti']).first()
        if block_token:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token is already block")
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid Token")
    user_id=Authorize.get_jwt_subject()

    data=  db.query(RoleUserModel).filter(and_(RoleUserModel.user_id ==user_id,RoleUserModel.jti==mak['jti'])).first()
    
    if data is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid Token")
    
    data2=  db.query(RoleModel).filter(RoleModel.uid ==data.role_id).first()

    if data2 is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Role Not Found")
    if data2.active==True:
        if data2.role['user_management']=='a':
            if data.active==True:
                data=db.query(RoleUserModel).options(load_only(*['name',"uid"])).all()
                data=db.query(RoleUserModel).all()
                result = [{"uid": item.uid, "name": item.name} for item in data]
                
                return {'status_code': status.HTTP_201_CREATED, 'success': True, 'data': result}
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail="User is not active")
            
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="This Role is not permitted for you")
    raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Role is not active")


