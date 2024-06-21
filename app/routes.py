from flask import Blueprint,request,jsonify
from . import db
from .utils import (encrypt_symmetric,decrypt_symmetric,encrypt_asymmetric,decrypt_asymmetric,sign_data,verify_signature,generate_key,encrypt_private_key,decrypt_private_key)
from .models import (User,SymmetricKey,AsymmetricKeyPair,EncryptedData)

main=Blueprint('main',__name__)

#Define endpoints
#Define route handlers for our API

@main.route('/encrypt-symmetric', methods=['POST'])
def encrypt_symmetric_route():
    #get parameters
    data=request.json.get('data')
    key=request.json.get('key')
    #error handling
    if not data:
        return jsonify({'error':'Missing data parameter'}),400
    if not key:
        return jsonify({'error':'Missing key parameter'}),400
    encrypted_data = encrypt_symmetric(data, key)
    return jsonify({'encrypted_data': encrypted_data})

@main.route('/decrypt-symmetric', methods=['POST'])
def decrypt_symmetric_route():
    #get parameters
    data=request.json.get('data')
    key=request.json.get('key')
    #error handling
    if not data:
        return jsonify({'error':'Missing data parameter'}),400
    if not key:
        return jsonify({'error':'Missing key parameter'}),400
    decrypted_data = decrypt_symmetric(data, key)
    return jsonify({'decrypted_data': decrypted_data})

@main.route('/encrypt-asymmetric', methods=['POST'])
def encrypt_asymmetric_route():
    #get parameters
    data=request.json.get('data')
    key=request.json.get('key')
    #error handling
    if not data:
        return jsonify({'error':'Missing data parameter'}),400
    if not key:
        return jsonify({'error':'Missing key parameter'}),400
    encrypted_data = encrypt_asymmetric(data, key)
    return jsonify({'encrypted_data': encrypted_data})

@main.route('/decrypt-asymmetric', methods=['POST'])
def decrypt_asymmetric_route():
    #Get data and key
    data=request.json.get('data')
    key=request.json.get('key')
    #error handling
    if not data:
        return jsonify({'error':'Missing data parameter'}),400
    if not key:
        return jsonify({'error':'Missing key parameter'}),400
    decrypted_data = decrypt_asymmetric(data, key)
    return jsonify({'decrypted_data': decrypted_data})

@main.route('/hash', methods=['POST'])
def hash_route():
    #get data
    data=request.json.get('data')
    #error handling
    if not data:
        return jsonify({'error':'Missing data parameter'}),400
    if not isinstance(data,str):
        return jsonify({'error':'Only string argument can be hashed'}),400
    hash_data = hash(data)
    return jsonify({'hash_data': hash_data})

@main.route('/verify-hash',methods=['POST'])
def verify_hash_route():
    #get parameters
    data=request.json.get('data')
    received_hash=request.json.get('hash')
    #error handling
    if not data:
        return jsonify({'error':'Missing data parameter'}),400
    if not received_hash:
        return jsonify({'error':'Missing hash data parameter'}),400
    #compute the hash from received data
    computed_hash=hash(data)
    #verify hash by compared received and computed hash
    if computed_hash ==received_hash:
        return jsonify({'message':'Hash verification successful'}), 200
    else:
        return jsonify({'error':'Hash verification failed'}), 400

@main.route('/sign', methods=['POST'])
def sign_route():
    #get parameters
    data=request.json.get('data')
    key=request.json.get('key')
    #error handling
    if not data:
        return jsonify({'error':'Missing data parameter'}),400
    if not key:
        return jsonify({'error':'Missing key parameter'}),400
    signature = sign_data(data, key)
    return jsonify({'signature': signature})

@main.route('/verify-signature', methods=['POST'])
def verify_signature_route():
    #get parameters
    data=request.json.get('data')
    signature=request.json.get('signature')
    key=request.json.get('key')
    #error handling
    if not data:
        return jsonify({'error':'Missing data parameter'}),400
    if not key:
        return jsonify({'error':'Missing key parameter'}),400
    if not signature:
        return jsonify({'error':'Missing signature parameter'}),400
    verified = verify_signature(data, signature, key)
    if verified:
        return jsonify('Signature verified'),200
    else:
        return jsonify({'error':'Signature and key do not match'}),400
    
@main.route('/generate-key',methods=['POST'])
def generate_key_route():
    #get type and algorithm
    type=request.json.get('type')
    algorithm=request.json.get('algorithm')
    #error handling
    if type not in ['symmetric', 'asymmetric']:
        return jsonify({'error': 'Invalid key type. Must be "symmetric" or "asymmetric".'}), 400 
    if type == 'symmetric' and algorithm != 'AES':
        return jsonify({'error': 'Invalid algorithm for symmetric key. Must be "AES".'}), 400
    if type == 'asymmetric' and algorithm != 'RSA':
        return jsonify({'error': 'Invalid algorithm for asymmetric key. Must be "RSA".'}), 400
    #generate keys
    keys=generate_key(type,algorithm)
    if keys is None:
        return jsonify({'error': 'Failed to generate key(s).'}), 500
    if type == 'symmetric':
        return jsonify({'key': keys})
    elif type == 'asymmetric':
        private_key, public_key = keys
        return jsonify({'private_key': private_key, 'public_key': public_key})

@main.route('/store-key',methods=[POST])
def store_key_route():
    

@main.route('/create-user',methods=['POST'])
def create_user_route():
    #get user data
    username=request.json.get('username')
    email=request.json.get('email')
    password=request.json.get('password')
    #error handling
    if not username or not email or not password:
        return jsonify({'Error':'Missing input.'}),400
    # Check if username already exists in the database
    existing_user = User.query.filter_by(username=username).first()
    if existing_user:
        return jsonify({'Error': 'Username already exists. Please choose a different username.'}), 400
    #create new user and store in db
    new_user=User(username=username,email=email,password=password)
    db.session.add(new_user)
    db.session.commit()
    return jsonify({'message': 'User created successfully'}), 201
