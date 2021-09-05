import jwt
import os
import uuid

from datetime import datetime, timedelta
from flask import Flask, request, jsonify, make_response
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)


directorio = os.path.abspath(os.path.dirname(__file__))
app.config['SECRET_KEY'] = 'Dramyson1024'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' +\
                            os.path.join(directorio, 'todo.sqlite')

db = SQLAlchemy(app)
Migrate(app, db)


class User(db.Model):
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


@app.route('/user', methods=['GET'])
def get_all_users():
    users = User.query.all()
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
def get_one_user(public_id):
    user = User.query.filter_by(public_id=public_id).first()

    if not user:
        return jsonify({'messaje': 'Usuario no encontrado!'})

    user_data = {}
    user_data['public_id'] = user.public_id
    user_data['name'] = user.name
    user_data['password'] = user.password
    user_data['admin'] = user.admin

    return jsonify({'users': user_data})


@app.route('/user', methods=['POST'])
def create_user():
    data = request.get_json()
    hashed_password = generate_password_hash(data['password'], method='sha256')
    new_user = User(
                    public_id=str(uuid.uuid4()),
                    name=data['name'],
                    password=hashed_password,
                    admin=False)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({'message': 'Nuevo usuario creado'})


@app.route('/user/<public_id>', methods=['PUT'])
def promote_user(public_id):
    user = User.query.filter_by(public_id=public_id).first()

    if not user:
        return jsonify({'messaje': 'Usuario no encontrado!'})

    user.admin = True
    db.session.commit()

    return jsonify({'messaje': 'El usuaro ha sido promovido'})


@app.route('/user/<public_id>', methods=['DELETE'])
def delete_user(public_id):
    user = User.query.filter_by(public_id=public_id).first()

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

    user = User.query.filter_by(name=auth.username).first()

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


# if __name__ == '__main__':
#     app.run(debug=True)
