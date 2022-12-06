import re
import sys
from typing import Optional
from passlib.context import CryptContext
from auth_sys.data_access.user_data import UserData
from auth_sys.entity.user import User
from auth_sys.exception import FaceAppException
from auth_sys.logger import logging

bcrypt_context = CryptContext(schemes = ["bcrypt"], deprecated="auto")

class LoginValidation:

    def __init__(self,email_id: str, password:str):
        try:
            self.email_id = email_id
            self.password = password
            self.regex = re.compile(
                r"([A-Za-z0-9]+[.-_])*[A-Za-z0-9]+@[A-Za-z0-9-]+(\.[A-Z|a-z]{2,})+"
            )
        except Exception as e:
            raise FaceAppException(e,sys)

    def validate(self) -> bool:
        '''Validate the user input'''
        try:
            msg = ""
            if not self.email_id:
                msg += "Email Id is required"
            if not self.password:
                msg += "Password is required"
            if not self.is_email_valid():
                msg += "Invalid Email Id"
            return msg
        except Exception as e:
            raise FaceAppException(e,sys)

    def is_email_valid(self) -> bool:
        '''Check if email id is valid'''
        try:
            if re.fullmatch(self.regex, self.email_id):
                return True
            else:
                return False
        except Exception as e:
            raise FaceAppException(e,sys)

    def verify_password(self, plain_password: str, hashed_password: str) -> bool:
        '''Verify hashed password and plain password'''
        try:
            return bcrypt_context.verify(plain_password, hashed_password)
        except Exception as e:
            raise FaceAppException(e,sys)

    def validate_login(self) -> dict:
        '''checks all the validation conditions for the user registration'''
        try:
            if len(self.validate()) != 0:
                return {"status": False, "msg": self.validate()}
            return {"status":True}
        except Exception as e:
            raise FaceAppException(e,sys)
    
    def authenticate_user_login(self) -> Optional[str]:
        '''Authenticate the user and return token 
        if authentication successful'''
        try:
            logging.info("Authenticating the user details")
            if self.validate_login()["status"]:
                userdata = UserData()
                logging.info("Fetching the user details from the database")
                user_login_val = userdata.get_user({"email_id": self.email_id})
                if not user_login_val:
                    logging.info("User not found with login details")
                    return False
                if not self.verify_password(self.password, user_login_val["password"]):
                    logging.info("Password is incorrect")
                    return False
                logging.info("User authenticated successfully....")
                return user_login_val
            return False
        except Exception as e:
            raise FaceAppException(e, sys) from e































































































