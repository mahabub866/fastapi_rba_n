from fastapi import HTTPException,status
from dotenv import load_dotenv
import os
import jwt
from fastapi_jwt_auth.exceptions import JWTDecodeError
from models import BlockModel,RoleUserModel
from fastapi_jwt_auth import AuthJWT
from sqlalchemy import asc,or_,desc,and_

load_dotenv()

AUTHJWT_SECRET_KEY=os.getenv("AUTHJWT_SECRET_KEY")
algo=os.getenv("authjwt_decode_algorithms")

authjwt = AuthJWT()
denylist = set()



def flatten_list_of_dicts(lst):
    result = []
    for item in lst:
        if isinstance(item, list):
            result.extend(flatten_list_of_dicts(item))
        elif isinstance(item, dict):
            result.append(item)
    return result

def authfuncjti(data,db):
    # print(data,db,'ddddddddddddddddddddddd')
    try:
        # Your code for decoding the token
        
        block_token=db.query(BlockModel).filter(BlockModel.jti==data).first()
        # print(block_token.jti,'dddddddddddddddddd')
        if block_token is not None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token is already block")
        # if block_token is not None:
        #     raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token is already block")
            
        # main=db.query(RoleUserModel).filter(RoleUserModel.user_id==payload["sub"]).first()
        # print(main,'ddddddddddddddd')
        # user_main=db.query(RoleUserModel).filter(RoleUserModel.user_id==payload["sub"]).first()
        # if main is None :
        #     decode_value_user=jwt.decode(data,AUTHJWT_SECRET_KEY,algorithms=[algo])
        #     if decode_value_user['jti']!=payload["jti"]:
        #         return 'Token Block'
        # if user_main :
        #     decode_value=jwt.decode(data,AUTHJWT_SECRET_KEY,algorithms=[algo])
        #     if decode_value['jti']!=payload["jti"]:
        #         return 'Token Block'
        # if main  is None and user_main is None:
        #     return 'Token Block'
        # if main is None and user_main:
        #     decode_value_user=decode_token(user_main.token)
        #     if decode_value_user['jti']!=payload["jti"]:
        #         return 'Token Block'
        # if main and user_main is None:
        #     decode_value=decode_token(main.token)
        #     if decode_value['jti']!=payload["jti"]:
        #         return 'Token Block'
       
        return block_token
    except JWTDecodeError as e:
         # Handle JWTDecodeError (e.g., token expired)
        return {"error": "Token has expired."}, 401
    except jwt.ExpiredSignatureError:
        print("Token has expired.")
    except jwt.InvalidTokenError:
        print("Invalid token.")
    except jwt.DecodeError:
        print("Not a valid JWT.")
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="JWT token has expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid JWT token")

def decode_token(data,db):
    # print(data,db,'fffffffffffffffffffffffffffffffffffffffffffffffffff')
    try:
        # Your code for decoding the token
        payload = jwt.decode(data,AUTHJWT_SECRET_KEY,algorithms=[algo])
        # print(payload,'fjaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa')
        # print(payload['sub'],'fjaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa')
        block_tokens=db.query(BlockModel).filter(BlockModel.user_id==payload['sub']).count()
        if block_tokens>=20:
            delete=db.query(BlockModel).filter(BlockModel.user_id == payload["sub"]).order_by(asc(BlockModel.create_at)).first()
            # print(delete)
            db.delete(delete)
            db.commit()
            denylist = set()
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
                return 'Token Block'
        if user_main :
            decode_value=jwt.decode(data,AUTHJWT_SECRET_KEY,algorithms=[algo])
            if decode_value['jti']!=payload["jti"]:
                return 'Token Block'
        # if main  is None and user_main is None:
        #     return 'Token Block'
        # if main is None and user_main:
        #     decode_value_user=decode_token(user_main.token)
        #     if decode_value_user['jti']!=payload["jti"]:
        #         return 'Token Block'
        # if main and user_main is None:
        #     decode_value=decode_token(main.token)
        #     if decode_value['jti']!=payload["jti"]:
        #         return 'Token Block'
       
        return payload
    except JWTDecodeError as e:
         # Handle JWTDecodeError (e.g., token expired)
        return {"error": "Token has expired."}, 401
    except jwt.ExpiredSignatureError:
        print("Token has expired.")
    except jwt.InvalidTokenError:
        print("Invalid token.")
    except jwt.DecodeError:
        print("Not a valid JWT.")
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="JWT token has expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid JWT token")
