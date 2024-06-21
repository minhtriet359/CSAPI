from . import db

class SymmetricKey(db.Model):
    id=db.Column(db.Integer,primary_key=True)
    key=db.Column(db.Text,nullable=True)
    created_at=db.Column(db.DateTime,default=db.func.current_timestamp())

class AsymmetricKeyPair(db.Model):
    id=db.Column(db.Integer,primary_key=True)
    public_key=db.Column(db.Text,nullable=True)
    private_key=db.Column(db.Text,nullable=True)
    created_at=db.Column(db.DateTime,default=db.func.current_timestamp())

class EncryptedData(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    data = db.Column(db.Text, nullable=False)
    key_version = db.Column(db.Integer, nullable=False)

