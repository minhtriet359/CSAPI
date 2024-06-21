from . import db
from sqlalchemy.orm import relationship
from werkzeug.security import generate_password_hash, check_password_hash


class User(db.Model):
    id=db.Column(db.Integer,primary_key=True)
    username=db.Column(db.String(20),nullable=False,unique=True)
    password=db.Column(db.String(20),nullable=False)
    encrypted_data=relationship('EncryptedData',backref='user',lazy=True)
    symmetric_key=relationship('SymmetricKey',backref='user',lazy=True)
    asymmetric_key_pairs=relationship('AsymmetricKeyPair',backref='user',lazy=True)
    def set_password(self, password):
        self.password = generate_password_hash(password)
    def check_password(self, password):
        return check_password_hash(self.password, password)

class SymmetricKey(db.Model):
    id=db.Column(db.Integer,primary_key=True)
    key=db.Column(db.Text,nullable=False)
    created_at=db.Column(db.DateTime,default=db.func.current_timestamp())
    user_id=db.Column(db.Integer,db.ForeignKey('user.id'),nullable=False)

class AsymmetricKeyPair(db.Model):
    id=db.Column(db.Integer,primary_key=True)
    public_key=db.Column(db.Text,nullable=False)
    private_key=db.Column(db.Text,nullable=False)
    created_at=db.Column(db.DateTime,default=db.func.current_timestamp())
    user_id=db.Column(db.Integer,db.ForeignKey('user.id'),nullable=False)
