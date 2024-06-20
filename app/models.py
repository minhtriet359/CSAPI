from . import db

class User(db.Model):
    id=db.Column(db.Integer,primary_key=True)
    username=db.Column(db.String(20),nullable=True)
    password=db.Column(db.String(20),nullable=True)
    email=db.Column(db.String(50),nullable=True)
    symmetric_keys=db.relationship('SymmetricKey',backref='user',lazy=True)
    asymmetric_keys=db.relationship('AsymmetricKeyPair',backref='user',lazy=True)
    encrypted_data=db.relationship('EncryptedData',backref='user',lazy=True)


class SymmetricKey(db.Model):
    id=db.Column(db.Integer,primary_key=True)
    private_key=db.Column(db.Text,nullable=True)
    created_at=db.Column(db.DateTime,default=db.func.current_timestamp())
    user_id=db.Column(db.Integer,db.ForeignKey('user.id'),nullable=False)

class AsymmetricKeyPair(db.Model):
    id=db.Column(db.Integer,primary_key=True)
    public_key=db.Column(db.Text,nullable=True)
    private_key=db.Column(db.Text,nullable=True)
    created_at=db.Column(db.DateTime,default=db.func.current_timestamp())
    user_id=db.Column(db.Integer,db.ForeignKey('user.id'),nullable=False)

class EncryptedData(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    data = db.Column(db.Text, nullable=False)
    key_version = db.Column(db.Integer, nullable=False)
    user_id=db.Column(db.Integer,db.ForeignKey('user.id'),nullable=False)

