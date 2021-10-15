import jwt
import uuid

from datetime import datetime, timedelta
from functools import wraps
from flask import request, jsonify, make_response
from werkzeug.security import generate_password_hash, check_password_hash

from modules.processors import Processors

from main import app


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):

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
def get_user(current_user):

    if not current_user.admin:
        return jsonify({"message": "No puede realizar esta función," + " " +
                                "no eres un usuario administrador"})

    output = Processors().get_all_users_processor()
    return jsonify({"users": output})


@app.route("/user/<public_id>", methods=["GET"])
@token_required
def consulta_usuario(usuario_actual, public_id):

    if not usuario_actual.admin:
        return jsonify({"message": "No puede realizar esta función," + " " +
                                "no eres un usuario administrador"})

    user = Usuario.query.filter_by(public_id=public_id).first()

    if not user:
        return jsonify({"messaje": "Usuario no encontrado!"})

    user_data = {}
    user_data["public_id"] = user.public_id
    user_data["name"] = user.name
    user_data["password"] = user.password
    user_data["admin"] = user.admin

    return jsonify({"users": user_data})


@app.route("/user", methods=["POST"])
def creacion_de_usuario(usuario_actual):

    if not usuario_actual.admin:
        return jsonify({"message": "No puede realizar esta función," + " " +
                                "no eres un usuario administrador"})

    data = request.get_json()
    hashed_password = generate_password_hash(data["password"], method="sha256")
    new_user = Usuario(
                    public_id=str(uuid.uuid4()),
                    name=data["name"],
                    password=hashed_password,
                    admin=False)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({"message": "Nuevo usuario creado"})


@app.route("/user/<public_id>", methods=["PUT"])
@token_required
def administrador(usuario_actual, public_id):

    if not usuario_actual.admin:
        return jsonify({"message": "No puede realizar esta función," + " " +
                                "no eres un usuario administrador"})

    user = Usuario.query.filter_by(public_id=public_id).first()

    if not user:
        return jsonify({"messaje": "Usuario no encontrado!"})

    user.admin = True
    db.session.commit()

    return jsonify({"messaje": "El usuario ha sido promovido y es ahora administrador"})


@app.route("/user/<public_id>", methods=["DELETE"])
@token_required
def borrar_usuario(usuario_actual, public_id):

    if not usuario_actual.admin:
        return jsonify({"message": "No puede realizar esta función," + " " +
                                "no eres un usuario administrador"})

    user = Usuario.query.filter_by(public_id=public_id).first()

    if not user:
        return jsonify({"messaje": "Usuario no encontrado!"})
    db.session.delete(user)
    db.session.commit()

    return jsonify({"messaje": "El usuario ha sido eliminado correctamente"})


@app.route("/login")
def login():
    auth = request.authorization

    if not auth or not auth.username or not auth.password:
        return make_response(
                        "No pudo ser verificado",
                        401,
                        {
                            'www-Authenticate': 'Basic realm="Inicia Sesion!"'
                    }
                )

    user = Usuario.query.filter_by(name=auth.username).first()

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


@app.route("/todo", methods=["GET"])
@token_required
def consulta_de_usuarios_todos(usuario_actual):
    todos = Todo.query.filter_by(user_id=usuario_actual.id).all()

    output = []

    for todo in todos:
        todo_data = {}
        todo_data["id"] = todo.id
        todo_data["text"] = todo.text
        todo_data["complete"] = todo.complete
        output.append(todo_data)

    return jsonify({"todos": output})


@app.route("/todo/<todo_id>", methods=["GET"])
@token_required
def consulta_usuario_todo(usuario_actual, todo_id):
    todo = Todo.query.filter_by(id=todo_id, user_id=usuario_actual.id).first()

    if not todo:
        return jsonify({"message": "No se encontro el id"})

    todo_data = {}
    todo_data["id"] = todo.id
    todo_data["text"] = todo.text
    todo_data["complete"] = todo.complete

    return jsonify(todo_data)


@app.route("/todo", methods=["POST"])
@token_required
def creacion_de_usuario_todo(usuario_actual):
    data = request.get_json()

    new_todo = Todo(text=data["text"],
                    complete=False,
                    user_id=usuario_actual.id)
    db.session.add(new_todo)
    db.session.commit()
    return jsonify({"message": "Mensaje enviado"})


@app.route("/todo/<todo_id>", methods=["PUT"])
@token_required
def completa_todos(usuario_actual, todo_id):
    todo = Todo.query.filter_by(id=todo_id, user_id=usuario_actual.id).first()

    if not todo:
        return jsonify({"message": "No se encontro el id del usuario"})

    todo.complete = True
    db.session.commit()
    return jsonify({"message": "Todos los item han sido completados"})


@app.route("/todo/<todo_id>", methods=["DELETE"])
@token_required
def borrar_todo(usuario_actual, todo_id):
    todo = Todo.query.filter_by(id=todo_id, user_id=usuario_actual.id).first()

    if not todo:
        return jsonify({"message": "No se encontro el id del usuario"})

    db.session.delete(todo)
    db.session.commit()

    return jsonify({"message": "Todo el item ha sido borrado"})

