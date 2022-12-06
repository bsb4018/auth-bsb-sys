from datetime import datetime, timedelta
from typing import Optional
from fastapi import APIRouter, HTTPException, Request, Response, status
from jose import JWTError, jwt
from pydantic import BaseModel
from starlette.responses import JSONResponse, RedirectResponse

from auth_sys.validation.user_validation import LoginValidation, RegisterValidation
from auth_sys.constant.auth_constants import ALGORITHM, SECRET_KEY
from auth_sys.entity.user import User

class Login(BaseModel):
    '''Base Model for login'''
    email_id: str
    password: str

class Register(BaseModel):
    '''Base Model for register'''
    Name: str
    username: str
    email_id: str
    ph_no: str
    password1: str
    password2: str


router = APIRouter(
    prefix = "/auth",
    tags = ["auth"],
    response = {"401": {"description": "Not Authorized!"}},
)

def create_access_token(uuid: str, username: str, expires_delta: Optional[str] = None) -> str:
    '''Create an access token'''
    try:
        secret_key = SECRET_KEY
        algorithm = ALGORITHM

        encode = {"sub": uuid, "username": username}
        if expires_delta:
            expire = datetime.utcnow() + expires_delta
        else:
            expire = datetime.utcnow() + timedelta(minutes=15)
        encode.update({"exp": expire})
        return jwt.encode(encode, secret_key, algorithm=algorithm)
    except Exception as e:
        raise e

@router.post("/token")
async def login_for_access_token(response: Response, login) -> dict:
    '''Set access token'''
    try:
        user_validation = LoginValidation(login.email_id, login.password)
        user: Optional[str] = user_validation.authenticate_user_login()
        if not user:
            return {"status": False, "uuid": None, "response": response}
        token_expires = timedelta(minutes=15)
        token = create_access_token(
            user["UUID"], user["username"], expires_delta=token_expires
        )
        response.set_cookie(key="access_token", value=token, httponly=True)
        return {"status": True, "uuid": user["UUID"], "response": response}

    except Exception as e:
        msg = "Failed to set access token"
        response = JSONResponse(
            status_code=status.HTTP_404_NOT_FOUND, content={"message": msg}
        )
        return {"status": False, "uuid": None, "response": response}

@router.get("/", response_class = JSONResponse)
async def authentication_page(request: Request):
    '''Login GET route'''
    try:
        return JSONResponse(
            status_code=status.HTTP_200_OK, content={"message": "Authentication Page"}
        )
    except Exception as e:
        raise e

@router.post("/", response_class=JSONResponse)
async def login(request: Request, login: Login):
    '''User Login'''
    try:
        msg = "Login Successful"
        response = JSONResponse(
            status_code=status.HTTP_200_OK, content={"message": msg}
        )
        token_response = await login_for_access_token(response=response, login=login)
        if not token_response["status"]:
            msg = "Incorrect Username and password"
            return JSONResponse(
                status_code=status.HTTP_401_UNAUTHORIZED,
                content={"status": False, "message": msg},
            )
            
        response.headers["uuid"] = token_response["uuid"]
        return response
    except HTTPException:
        msg = "UnKnown Error"
        return JSONResponse(
            status_code=status.HTTP_401_UNAUTHORIZED,
            content={"status": False, "message": msg},
        )
    except Exception as e:
        msg = "User NOT Found"
        response = JSONResponse(
            status_code=status.HTTP_404_NOT_FOUND,
            content={"status": False, "message": msg},
        )
        return response

@router.get("/register", response_class=JSONResponse)
async def registration_page(request: Request):
    '''User Registration'''
    try:
        return JSONResponse(
            status_code=status.HTTP_200_OK, content={"message": "Registration Page"}
        )
    except Exception as e:
        raise e

@router.post("/register", response_class=JSONResponse)
async def register_user(request: Request, register: Register):
    '''Request to register a user'''
    try:
        name = register.Name
        username = register.username
        password1 = register.password1
        password2 = register.password2
        email_id = register.email_id
        ph_no = register.ph_no

        # Add uuid to the session
        user = User(name, username, email_id, ph_no, password1, password2)
        request.session["uuid"] = user.uuid_

        # Validation of the user input data to check the format of the data
        user_registration = RegisterValidation(user)

        validate_regitration = user_registration.validate_registration()
        if not validate_regitration["status"]:
            msg = validate_regitration["msg"]
            response = JSONResponse(
                status_code=status.HTTP_401_UNAUTHORIZED,
                content={"status": False, "message": msg},
            )
            return response

        # Save user if the validation is successful
        validation_status = user_registration.authenticate_user_registration()

        msg = "Registration Successful...Please Login to continue"
        response = JSONResponse(
            status_code=status.HTTP_200_OK,
            content={"status": True, "message": validation_status["msg"]},
            headers={"uuid": user.uuid_},
        )
        return response
    except Exception as e:
        raise e


@router.get("/logout")
async def logout(request: Request):
    try:
        msg = "You have been logged out"
        response =  RedirectResponse(url="/auth/", status_code=status.HTTP_302_FOUND, headers={"msg": msg})
        response.delete_cookie(key="access_token")
        response = JSONResponse(
            status_code=status.HTTP_200_OK, content={"status": True, "message": msg}
        )
        return response
    except Exception as e:
        raise e


async def get_current_user(request: Request):
    '''Return the username and uuid of the current user'''
    try:
        secret_key = SECRET_KEY
        algorithm = ALGORITHM

        token = request.cookies.get("access_token")
        if token is None:
            return None
        
        payload = jwt.decode(token, secret_key, algorithms = [algorithm])
        uuid: str = payload.get("sub")
        username: str = payload.get("username")

        if uuid is None or username is None:
            return logout(request)
        
        return {"uuid": uuid, "username": username}
    except JWTError:
        raise HTTPException(status_code=404, detail = "User Details Not Found")
    except Exception as e:
        msg = "Error while getting current user"
        response = JSONResponse(
            status_code=status.HTTP_404_NOT_FOUND, content={"message": msg}
        )
        return response
        

























































































































