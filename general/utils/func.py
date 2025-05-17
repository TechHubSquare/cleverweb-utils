
import bcrypt
import datetime
from typing import Any, Union
from fastapi.responses import JSONResponse
from fastapi.security import HTTPBearer
import jwt
from pydantic import BaseModel
from fastapi import HTTPException, Request, Security
from passlib.context import CryptContext
from decouple import config


oauth2_scheme = HTTPBearer()

# Secret key for JWT
SECRET_KEY = config('SECRET_KEY', default="")
ALGORITHM = config('ALGORITHM', default="")
ACCESS_TOKEN_EXPIRE_MINUTES = config('ACCESS_TOKEN_EXPIRE_MINUTES', default=86400, cast=int)
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


class ResponseSchema(BaseModel):
    detail: Any
    status: Any

class XResponse:
    def __init__(self, success:bool, data:Union[ResponseSchema, Any], message:Any, status_code:int):
        self.success = success
        self.data = data
        self.message = message
        self.status_code = status_code
        
    @property
    def response(self):
        return JSONResponse(
                status_code=self.status_code,
                content={
                    'success':self.success, 'data':self.data,
                    'message':self.message, 'status_code':self.status_code
                }
            )
        


def hash_password(password: str) -> str:
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed_password.decode('utf-8')

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def create_access_token(data: dict):
    expires_delta: int = ACCESS_TOKEN_EXPIRE_MINUTES
    to_encode = data.copy()
    expire = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=expires_delta)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)




def verify_token(token: str = Security(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return JSONResponse(
            status_code=200,
            content=payload
        )
    except jwt.ExpiredSignatureError:
        # raise HTTPException(status_code=401, detail="Token expired")
        return XResponse(
                message='Token expired', status_code=401,
                data=None, success=False
            ).response
    except jwt.InvalidTokenError:
        # raise HTTPException(status_code=401, detail="Invalid token")
        return XResponse(
                    message='Invalid Token', status_code=401,
                    data=None, success=False
                ).response




def getToken(request:Request):
    token = request.headers.get('authorization', None)
    if token:
        striped = str(token).split('Bearer')[1].strip()
        return striped
    return None

