from app import create_app,db
from flask_migrate import Migrate,upgrade
import os

app=create_app()

if __name__=="__main__":
    with app.app_context():
        db.drop_all()
        db.create_all() #create database tables if they dont exist
    app.run(debug=True)