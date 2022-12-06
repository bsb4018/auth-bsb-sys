from auth_sys.config.database import MongodbClient
from auth_sys.constant.database_constants import EMBEDDING_COLLECTION_NAME
from auth_sys.exception import FaceAppException
import sys

class UserEmbeddingData:
    '''Gets user embedding data from database and
    saves user embedding data to database'''

    def __init__(self) -> None:
        try:
            self.client = MongodbClient()
            self.collection_name = EMBEDDING_COLLECTION_NAME
            self.collection = self.client.database[self.collection_name]
        except Exception as e:
            raise FaceAppException(e, sys)

    def save_user_embedding(self, uuid_: str, embedding_list) -> None:
        try:
            self.collection.insert_one({"UUID": uuid_, "user_embed": embedding_list})
        except Exception as e:
            raise FaceAppException(e, sys)

    def get_user_embedding(self, uuid_: str) -> dict:
        try:
            user: dict = self.collection.find_one({"UUID": uuid_})
            if user != None:
                return user
            else:
                return None
        except Exception as e:
            raise FaceAppException(e, sys)
        

























