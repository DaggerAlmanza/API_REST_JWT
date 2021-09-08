import jwt
import os
import uuid

from datetime import datetime, timedelta
from functools import wraps
from flask import Flask, request, jsonify, make_response
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)


directorio = os.path.abspath(os.path.dirname(__file__))
app.config['SECRET_KEY'] = 'Dramyson1024'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' +\
                            os.path.join(directorio, 'todo.sqlite')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
Migrate(app, db)


class Usuario(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String(50), unique=True)
    name = db.Column(db.String(50))
    password = db.Column(db.String(80))
    admin = db.Column(db.Boolean)


class Todo(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.String(50))
    complete = db.Column(db.Boolean)
    user_id = db.Column(db.Integer)


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):

        token = None

        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']

        if not token:
            return jsonify({'message': 'Falta el token!'}), 401

        try:
            data = jwt.decode(token,
                              app.config['SECRET_KEY'],
                              algorithms='HS256')
            usuario_actual = Usuario.query.filter_by(
                                    public_id=data['public_id']).first()
        except:
            return jsonify({'message': 'El token es invalido'})

        return f(usuario_actual, *args, **kwargs)

    return decorated


@app.route('/user', methods=['GET'])
@token_required
def consulta_de_usuarios(usuario_actual):

    if not usuario_actual.admin:
        return jsonify({'message': 'No puede realizar esta función,' + ' ' +
                                'no eres un usuario administrador'})

    users = Usuario.query.all()
    output = []

    for user in users:
        user_data = {}
        user_data['public_id'] = user.public_id
        user_data['name'] = user.name
        user_data['password'] = user.password
        user_data['admin'] = user.admin
        output.append(user_data)
    return jsonify({'users': output})


@app.route('/user/<public_id>', methods=['GET'])
@token_required
def consulta_usuario(usuario_actual, public_id):

    if not usuario_actual.admin:
        return jsonify({'message': 'No puede realizar esta función,' + ' ' +
                                'no eres un usuario administrador'})

    user = Usuario.query.filter_by(public_id=public_id).first()

    if not user:
        return jsonify({'messaje': 'Usuario no encontrado!'})

    user_data = {}
    user_data['public_id'] = user.public_id
    user_data['name'] = user.name
    user_data['password'] = user.password
    user_data['admin'] = user.admin

    return jsonify({'users': user_data})


@app.route('/user', methods=['POST'])
@token_required
def creacion_de_usuario(usuario_actual):

    if not usuario_actual.admin:
        return jsonify({'message': 'No puede realizar esta función,' + ' ' +
                                'no eres un usuario administrador'})

    data = request.get_json()
    hashed_password = generate_password_hash(data['password'], method='sha256')
    new_user = Usuario(
                    public_id=str(uuid.uuid4()),
                    name=data['name'],
                    password=hashed_password,
                    admin=False)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({'message': 'Nuevo usuario creado'})


@app.route('/user/<public_id>', methods=['PUT'])
@token_required
def administrador(usuario_actual, public_id):

    if not usuario_actual.admin:
        return jsonify({'message': 'No puede realizar esta función,' + ' ' +
                                'no eres un usuario administrador'})

    user = Usuario.query.filter_by(public_id=public_id).first()

    if not user:
        return jsonify({'messaje': 'Usuario no encontrado!'})

    user.admin = True
    db.session.commit()

    return jsonify({'messaje': 'El usuario ha sido promovido y es ahora administrador'})


@app.route('/user/<public_id>', methods=['DELETE'])
@token_required
def borrar_usuario(usuario_actual, public_id):

    if not usuario_actual.admin:
        return jsonify({'message': 'No puede realizar esta función,' + ' ' +
                                'no eres un usuario administrador'})

    user = Usuario.query.filter_by(public_id=public_id).first()

    if not user:
        return jsonify({'messaje': 'Usuario no encontrado!'})
    db.session.delete(user)
    db.session.commit()

    return jsonify({'messaje': 'El usuario ha sido eliminado correctamente'})


@app.route('/login')
def login():
    auth = request.authorization

    if not auth or not auth.username or not auth.password:
        return make_response(
                            'No pudo ser verificado',
                            401, {
                             'www-Authenticate': 'Basic realm="Inicia Sesion!"'
                                }
                            )

    user = Usuario.query.filter_by(name=auth.username).first()

    if not user:
        return make_response(
                            'No pudo ser verificado',
                            401, {
                             'www-Authenticate': 'Basic realm="Inicia Sesion!"'
                                }
                            )

    if check_password_hash(user.password, auth.password):
        token = jwt.encode({
                            'public_id': user.public_id,
                            'exp': datetime.utcnow() +
                            timedelta(minutes=30)
                           },
                           app.config['SECRET_KEY'])

        return jsonify({'token': token})

    return make_response(
                            'No pudo ser verificado',
                            401, {
                             'www-Authenticate': 'Basic realm="Inicia Sesion!"'
                                }
                            )


@app.route('/todo', methods=['GET'])
@token_required
def consulta_de_usuarios_todos(usuario_actual):
    return ""


@app.route('/todo/<todo_id>', methods=['GET'])
@token_required
def consulta_usuario_todo(usuario_actual, todo_id):
    return ""


@app.route('/todo', methods=['POST'])
@token_required
def creacion_de_usuario_todo(usuario_actual):
    data = request.get_json()

    new_todo = Todo(text=data['text'],
                    complete=False,
                    user_id=usuario_actual.id)
    db.session.add(new_todo)
    db.session.commit()
    return jsonify({'message': 'Mensaje enviado'})


@app.route('/todo/<todo_id>', methods=['PUT'])
@token_required
def completa_todos(usuario_actual, todo_id):
    return ""


@app.route('/todo/<todo_id>', methods=['DELETE'])
@token_required
def borrar_todo(usuario_actual, todo_id):
    return ""

# if __name__ == '__main__':
#     app.run(debug=True)