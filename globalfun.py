from fastapi import HTTPException,status
from dotenv import load_dotenv
import os
import jwt
from fastapi_jwt_auth.exceptions import JWTDecodeError
from models import BlockModel,RoleUserModel,RoleModel
from fastapi_jwt_auth import AuthJWT
from sqlalchemy import asc,or_,desc,and_

load_dotenv()

AUTHJWT_SECRET_KEY=os.getenv("AUTHJWT_SECRET_KEY")
algo=os.getenv("authjwt_decode_algorithms")

authjwt = AuthJWT()
denylist = set()



def flatten_list_of_dicts(logs):
    one_array_logs=[]
    for item in logs:
        if isinstance(item, list):
            one_array_logs.extend(item)
        elif isinstance(item, dict):
            one_array_logs.append(item)
    return one_array_logs


def decode_token(data,db,):
    # print(data,'fffffffffffffffffffffffffffffffffffffffffffffffffff')
    try:
        # Your code for decoding the token
        # print(data)
        payload = jwt.decode(data,AUTHJWT_SECRET_KEY,algorithms=[algo])

        block_tokens=db.query(BlockModel).filter(BlockModel.user_id==payload['sub']).count()
        if block_tokens>=20:
            delete=db.query(BlockModel).filter(BlockModel.user_id == payload["sub"]).order_by(asc(BlockModel.create_at)).first()
            # print(delete)
            db.delete(delete)
            db.commit()
            denylist(payload['jti'])
            jti = payload['jti']
            if jti in denylist:
                return True
            return payload
        block_token=db.query(BlockModel).filter(BlockModel.jti==payload["jti"]).first()
        # print(block_token,'dddddddddddddddddd')
        if block_token is not None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token is already block")
            
        main=db.query(RoleUserModel).filter(RoleUserModel.user_id==payload["sub"]).first()
        # print(main,'ddddddddddddddd')
        user_main=db.query(RoleUserModel).filter(RoleUserModel.user_id==payload["sub"]).first()
        if main is None :
            decode_value_user=jwt.decode(data,AUTHJWT_SECRET_KEY,algorithms=[algo])
            if decode_value_user['jti']!=payload["jti"]:
                raise HTTPException(status_code=401, detail="Block Token")
        if user_main :
            decode_value=jwt.decode(data,AUTHJWT_SECRET_KEY,algorithms=[algo])
            if decode_value['jti']!=payload["jti"]:
                raise HTTPException(status_code=401, detail="Block Token")
        if main  is None and user_main is None:
            print("Token Block")
            return None
        if main is None and user_main:
            decode_value_user=decode_token(user_main.token)
            if decode_value_user['jti']!=payload["jti"]:
                print("Token Block")
                return None
        if main and user_main is None:
            decode_value=decode_token(main.token)
            if decode_value['jti']!=payload["jti"]:
                print("Token Block")
                return None
       
        return payload
    except JWTDecodeError as e:
        print("JWT token has expired")
        return None
        # raise HTTPException(status_code=401, detail="JWT token has expired")
    except jwt.ExpiredSignatureError as e:
        print("JWT token has expired")
        return None
        # raise HTTPException(status_code=401, detail="JWT token has expired")
    except jwt.InvalidTokenError:
        print("JWT token has expired")
        return None
        # raise HTTPException(status_code=401, detail="JWT token has expired")
    except jwt.DecodeError:
        print("JWT token has expired")
        return None
        # raise HTTPException(status_code=401, detail="JWT token has expired")
    except jwt.ExpiredSignatureError:
        print("JWT token has expired")
        return None
        # raise HTTPException(status_code=401, detail="JWT token has expired")
    except jwt.InvalidTokenError:
        print("JWT token has expired")
        return None
        # raise HTTPException(status_code=401, detail="Invalid JWT token")

def validation_user_management(user_id,db,jti):
    try:
        block_token=db.query(BlockModel).filter(BlockModel.jti==jti).first()
        if block_token:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token is already block")
    
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Token is Block")
    data=  db.query(RoleUserModel).filter(and_(RoleUserModel.user_id ==user_id,RoleUserModel.jti==jti)).first()
    
    if data is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="This token is not available")
    
    data2=  db.query(RoleModel).filter(RoleModel.uid ==data.role_id).first()

    if data2 is None:
        raise HTTPException(
           status_code=status.HTTP_404_NOT_FOUND, detail="Role Not Found")
    if data2.active==True:
        if data2.role['user_management']=='a':
            if data.active==True:

                return True
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail="User is not active")
            
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="This Role is not permitted for you")
    raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Role is not active")