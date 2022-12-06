from auth_sys.config.database import MongodbClient
from auth_sys.constant.database_constants import USER_COLLECTION_NAME
from auth_sys.entity.user import User
from auth_sys.exception import FaceAppException
import sys 

class UserData:
    "Gets user data from database and saves user data to database"

    def __init__(self) -> None:
        try:
            self.client = MongodbClient()
            self.collection_name = USER_COLLECTION_NAME
            self.collection = self.client.database[self.collection_name]
        except Exception as e:
            raise FaceAppException(e,sys)

    def save_user(self, user: User) -> None:
        try:
            self.collection.insert_one(user)
        except Exception as e:
            raise FaceAppException(e,sys)

    def get_user(self, query: dict):
        try:
            user = self.collection.find_one(query)
            return user
        except Exception as e:
            raise FaceAppException(e,sys)