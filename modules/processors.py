from modules.database import User


class Processors():

    def __init__(self) -> None:
        self.user_db = User()

    def get_user_processor(self, data: str) -> User:

        current_user = self.user_db.query.filter_by(
                                        public_id=data).first()
        return current_user

    def get_all_users_processor(self) -> list:

        users = self.user_db.query.all()
        output = []

        for user in users:
            user_data = {}
            user_data["public_id"] = user.public_id
            user_data["name"] = user.name
            user_data["password"] = user.password
            user_data["admin"] = user.admin
            output.append(user_data)
        return output
