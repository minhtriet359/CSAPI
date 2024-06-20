from flask import Flask
from flask_sqlalchemy import SQLAlchemy

#create database
db=SQLAlchemy()

#register application with blueprints
def create_app():
    app=Flask(__name__)
    app.config['SQLALCHEMY_DATABASE_URI']='sqlite:///crypto_service.db'
    db.init_app(app)
    from .routes import main as blueprint
    app.register_blueprint(blueprint)
    return app
