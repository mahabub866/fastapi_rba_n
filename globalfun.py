from fastapi import HTTPException,status

def authfunc(data):
    print(data,'ddddddddddddddd')
    try:
        data.jwt_required()
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid Token")

def get_data_from_jwt_token(token: str,auth_jwt):
    print(token,auth_jwt)
    try:
        decoded_token = auth_jwt.decode_token(token)
        # The 'decoded_token' will contain the decoded information from the JWT token
        return decoded_token
    except Exception as e:
        # Handle exceptions if the token is invalid, expired, etc.
        return None