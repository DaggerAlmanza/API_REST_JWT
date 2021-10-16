import uuid

from flask import json
from modules.database import User

from main import db


class Processors():

    def __init__(self) -> None:
        self.user_db = User
        self.db = db
        self.db.create_all()

    def get_data(self, user) -> dict:
        print(type(user))
        user_data = {}
        user_data["public_id"] = user.public_id
        user_data["name"] = user.name
        user_data["password"] = user.password
        user_data["admin"] = user.admin
        return user_data

    def get_user_processor(self, data: str):
        current_user = self.user_db.query.filter_by(
                                        public_id=data).first()
        return current_user

    def get_all_users_processor(self) -> list:

        users = self.user_db.query.all()
        output = []

        for user in users:
            user_data = self.get_data(user)
            output.append(user_data)
        return output

    def create_user_processor(
                        self,
                        data: json,
                        hashed_password: str):

        new_user = self.user_db(
                    public_id=str(uuid.uuid4()),
                    name=data["name"],
                    password=hashed_password,
                    admin=False)

        db.session.add(new_user)
        db.session.commit()

    def promote_user_processor(self, user):
        user.admin = True
        db.session.commit()

    def delete_user_processor(self, user):
        db.session.delete(user)
        db.session.commit()

    def login_processor(self, auth):
        user = self.user_db.query.filter_by(name=auth.username).first()
        return user
