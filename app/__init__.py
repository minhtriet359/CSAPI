from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager

#create database
db=SQLAlchemy()

#register application with blueprints
def create_app():
    app=Flask(__name__)
    app.config['SQLALCHEMY_DATABASE_URI']='sqlite:///crypto_service.db'
    app.config['JWT_SECRET_KEY'] = '12345'
    db.init_app(app)
    jwt = JWTManager(app)
    from .routes import main as blueprint
    app.register_blueprint(blueprint)
    return app
