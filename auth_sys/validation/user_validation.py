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
            raise FaceAppException(e, sys)

class RegisterValidation:
    def __init__(self, user: User) -> None:
        try:
            self.user = user
            self.regex = re.compile(
                r"([A-Za-z0-9]+[.-_])*[A-Za-z0-9]+@[A-Za-z0-9-]+(\.[A-Z|a-z]{2,})+"
            )
            self.uuid = self.user.uuid_
            self.userdata = UserData()
            self.bcrypt_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
        except Exception as e:
            raise FaceAppException(e, sys)

    
    def validate(self) -> bool:
        '''Checks all the validation conditions for 
        the user registration'''
        try:
            msg = ""
            if self.user.Name == None:
                msg += "Name is required"

            if self.user.username == None:
                msg += "Username is required"

            if self.user.email_id == None:
                msg += "Email is required"

            if self.user.ph_no == None:
                msg += "Phone Number is required"

            if self.user.password1 == None:
                msg += "Password is required"

            if self.user.password2 == None:
                msg += "Confirm Password is required"

            if not self.is_email_valid():
                msg += "Email is not valid"

            if not self.is_password_valid():
                msg += "Length of the password should be between 8 and 16"

            if not self.is_password_match():
                msg += "Password does not match"

            if not self.is_details_exists():
                msg += "User already exists"

            return msg
        except Exception as e:
            raise FaceAppException(e, sys)

    def is_email_valid(self) -> bool:
        '''true if email id is valid, false otherwise'''
        try:
            if re.fullmatch(self.regex, self.user.email_id):
                return True
            else:
                return False
        except Exception as e:
            raise FaceAppException(e, sys)
    
    def is_password_valid(self) -> bool:
        try:
            if len(self.user.password1) >= 8 and len(self.user.password2) <= 16:
                return True
            else:
                return False
        except Exception as e:
            raise FaceAppException(e, sys)

    def is_password_match(self) -> bool:
        try:
            if self.user.password1 == self.user.password2:
                return True
            else:
                return False
        except Exception as e:
            raise FaceAppException(e, sys)

    def is_details_exists(self) -> bool:
        try:
            username_val = self.userdata.get_user({"username": self.user.username})
            emailid_val = self.userdata.get_user({"email_id": self.user.email_id})
            uuid_val = self.userdata.get_user({"UUID": self.uuid})
            if username_val == None and emailid_val == None and uuid_val == None:
                return True
            return False
        except Exception as e:
            raise FaceAppException(e, sys)

    @staticmethod
    def get_password_hash(password: str) -> str:
        return bcrypt_context.hash(password)

    def validate_registration(self) -> bool:
        '''Checks all validation conditions for user registration'''
        try:
            if len(self.validate()) != 0:
                return {"status": False, "msg": self.validate()}
            return {"status": True}
        except Exception as e:
            raise FaceAppException(e, sys)

    def authenticate_user_registration(self) -> bool:
        '''This saves the user details in the database
        only after validating the user details'''
        try:
            logging.info("Validating the user details while Registration")
            if self.validate_registration()["status"]:
                logging.info("Generating the password hash")
                hashed_password: str = self.get_password_hash(self.user.password1)
                user_data_dict: dict = {
                    "Name": self.user.Name,
                    "username": self.user.username,
                    "password": hashed_password,
                    "email_id": self.user.email_id,
                    "ph_no": self.user.ph_no,
                    "UUID": self.uuid,
                }
                logging.info("Saving the user details in the database")
                self.userdata.save_user(user_data_dict)
                logging.info("Saving the user details in the database completed")
                return {"status": True, "msg": "User registered successfully"}
            logging.info("Validation failed while Registration")
            return {"status": False, "msg": self.validate()}
        except Exception as e:
            raise FaceAppException(e, sys)



















































































