from enum import unique
from os import name
from re import DEBUG
from typing import Text
from flask import Flask, app
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)

app.config['SECRET_KEY'] = 'Dramyson1024'
app.config[
    "SQLALCHEMY_DATABASE_URI"
] = "sqlite:////C:/Users\DAGER_RAFAEL\OneDrive\" +
    "Documentos\Proyectos\JSON Web Token\todo.db"

db = SQLAlchemy(app)

class User (db.Model):
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

if __name__ == '__main__':
    app.run(debug=True)
