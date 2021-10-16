import jwt

from datetime import datetime, timedelta
from functools import wraps
from flask import json, request, jsonify, make_response
from werkzeug.security import generate_password_hash, check_password_hash

from modules.processors import Processors

from main import app


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs) -> json:

        token = None

        if "x-access-token" in request.headers:
            token = request.headers["x-access-token"]

        if not token:
            return jsonify({"message": "Falta el token!"}), 401

        try:
            data = jwt.decode(
                token,
                app.config["SECRET_KEY"],
                algorithms="HS256")

            current_user = Processors().get_user_processor(data["public_id"])

        except Exception:

            return jsonify({"message": "El token es inválido"})

        return f(current_user, *args, **kwargs)

    return decorated


@app.route("/user", methods=["GET"])
@token_required
def get_all_users(current_user) -> json:
    """
    consulting every current user  in database, getting this dataset:
        admin": True o False,
        "name": "",
        "password": "",
        "public_id": ""
    Args:
        current_user ([type]): [description]

    Returns:
        json: 
        "users": all users
    """

    if not current_user.admin:
        return jsonify({"message": "No puede realizar esta función," + " " +
                                "no eres un usuario administrador"})

    output = Processors().get_all_users_processor()
    return jsonify({"users": output})


@app.route("/user/<public_id>", methods=["GET"])
@token_required
def get_one_user(current_user, public_id: str):

    if not current_user.admin:
        return jsonify({"message": "No puede realizar esta función," + " " +
                                "no eres un usuario administrador"})

    user = Processors().get_user_processor(public_id)

    if not user:
        return jsonify({"messaje": "Usuario no encontrado!"})

    user_data = Processors().get_data(user)

    return jsonify({"users": user_data})


@app.route("/user", methods=["POST"])
@token_required
def create_user(current_user) -> json:

    if not current_user.admin:
        return jsonify({"message": "No puede realizar esta función," + " " +
                                "no eres un usuario administrador"})

    data = request.get_json()
    hashed_password = generate_password_hash(data["password"], method="sha256")

    Processors().create_user_processor(data, hashed_password)

    return jsonify({"message": "Nuevo usuario creado"})


@app.route("/user/<public_id>", methods=["PUT"])
@token_required 
def promote_user(current_user, public_id: str) -> json:

    if not current_user.admin:
        return jsonify({"message": "No puede realizar esta función," + " " +
                                "no eres un usuario administrador"})

    user = Processors().get_user_processor(public_id)

    if not user:
        return jsonify({"messaje": "Usuario no encontrado!"})

    Processors().promote_user_processor(user)

    return jsonify(
        {"messaje": "El usuario ha sido promovido y es ahora administrador"}
    )


@app.route("/user/<public_id>", methods=["DELETE"])
@token_required
def delete_user(current_user, public_id: str) -> json:

    if not current_user.admin:
        return jsonify({"message": "No puede realizar esta función," + " " +
                                "no eres un usuario administrador"})

    user = Processors().get_user_processor(public_id)

    if not user:
        return jsonify({"messaje": "Usuario no encontrado!"})

    Processors().promote_user_processor(user)

    return jsonify({"messaje": "El usuario ha sido eliminado correctamente"})


@app.route("/login")
def login() -> json:
    auth = request.authorization

    if not auth or not auth.username or not auth.password:
        return make_response(
                        "No pudo ser verificado",
                        401,
                        {
                            'www-Authenticate': 'Basic realm="Inicia Sesion!"'
                    }
                )

    user = Processors().login_processor(auth)

    if not user:
        return make_response(
                        "No pudo ser verificado",
                        401,
                        {
                            'www-Authenticate': 'Basic realm="Inicia Sesion!"'
                    }
                )

    if check_password_hash(user.password, auth.password):
        token = jwt.encode({
                            "public_id": user.public_id,
                            "exp": datetime.utcnow() +
                            timedelta(minutes=30)
                        },
                        app.config["SECRET_KEY"])

        return jsonify({"token": token})

    return make_response(
                        "No pudo ser verificado",
                        401,
                        {
                            'www-Authenticate': 'Basic realm="Inicia Sesion!"'
                    }
                )
