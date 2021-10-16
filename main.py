from flask import Flask
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)

app.config["SECRET_KEY"] = "Dramyson1024"
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///userpool.sqlite"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)
