from flask import Flask


#register application with blueprints
def create_app():
    app=Flask(__name__)
    from .routes import main as blueprint
    app.register_blueprint(blueprint)
    return app
