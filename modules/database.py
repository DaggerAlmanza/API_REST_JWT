import os

from api_json_web_token import app
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy


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
