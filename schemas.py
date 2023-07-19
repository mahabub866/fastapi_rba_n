from pydantic import BaseModel,Field
from datetime import timedelta

class Settings(BaseModel):
    AUTHJWT_SECRET_KEY:str='mahabubea305b1b472fc85371e27dec1997!'
    authjwt_access_token_expires: timedelta = timedelta(hours=15)
    authjwt_refresh_token_expires: timedelta = timedelta(days=30)