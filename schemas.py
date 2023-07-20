from pydantic import BaseModel,Field
from datetime import timedelta
from dotenv import load_dotenv
import os

load_dotenv()

AUTHJWT_SECRET_KEY=os.getenv("AUTHJWT_SECRET_KEY")
algo=os.getenv("authjwt_decode_algorithms")


class Settings(BaseModel):
    AUTHJWT_SECRET_KEY:str=AUTHJWT_SECRET_KEY
    authjwt_denylist_enabled: bool = True
    authjwt_denylist_token_checks: set = {"access","refresh"}
    authjwt_decode_algorithms: set = {algo}
    authjwt_access_token_expires: timedelta = timedelta(hours=15)
    authjwt_refresh_token_expires: timedelta = timedelta(days=30)