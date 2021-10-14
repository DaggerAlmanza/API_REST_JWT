from modules.database import User, SuperUser


user_db = User()


def get_user_processor(data: str) -> User:
    """[summary]

    Args:
        data (str): [description]

    Returns:
        User: [description]
    """
    current_user = user_db.query.filter_by(
                                    public_id=data).first()
    return current_user


def get_all_users_processor() -> list:
    """[summary]

    Returns:
        list: [description]
    """

    users = user_db.query.all()
    output = []

    for user in users:
        user_data = {}
        user_data["public_id"] = user.public_id
        user_data["name"] = user.name
        user_data["password"] = user.password
        user_data["admin"] = user.admin
        output.append(user_data)
    return output
