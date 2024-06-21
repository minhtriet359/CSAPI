from flask import Blueprint,request,jsonify
from . import db
from .utils import (encrypt_symmetric,decrypt_symmetric,encrypt_asymmetric,decrypt_asymmetric,sign_data,verify_signature,generate_key,encrypt_private_key,decrypt_private_key)
from .models import (SymmetricKey,AsymmetricKeyPair,User)
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity

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
    
@main.route('/key/generate',methods=['POST'])
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

@main.route('/key/store',methods=['POST'])
@jwt_required()
def store_key_route():
    #get parameters
    current_user_username = get_jwt_identity()
    key_type=request.json.get('type')
    key_data=request.json.get('key')
    #validate parameters
    if not key_type or not key_data:
        return jsonify({'error': 'Missing required parameters.'}), 400
    if key_type not in ['symmetric', 'asymmetric']:
        return jsonify({'error': 'Invalid key type. Must be "symmetric" or "asymmetric".'}), 400
    try:
        #Get user for user id
        user = User.query.filter_by(username=current_user_username).first()
        if key_type == 'symmetric':
            symmetric_key = SymmetricKey(key=key_data,user_id=user.id)
            db.session.add(symmetric_key)
            db.session.commit()
            return jsonify({'message': 'Symmetric key stored successfully.'}), 201
        elif key_type == 'asymmetric':
            if not isinstance(key_data, dict) or 'private_key' not in key_data or 'public_key' not in key_data:
                return jsonify({'error': 'Invalid key data for asymmetric key.'}), 400
            private_key, public_key = key_data['private_key'], key_data['public_key']
            asymmetric_key = AsymmetricKeyPair(private_key=private_key, public_key=public_key,user_id=user)
            db.session.add(asymmetric_key)
            db.session.commit()
            return jsonify({'message': 'Asymmetric keys stored successfully.'}), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': f'Failed to store key: {str(e)}'}), 500

@main.route('/key/get',methods=['GET'])
@jwt_required()
def get_key_route():
    #get parameters
    current_user_username = get_jwt_identity()
    key_type=request.args.get('type')
    #validate parameters
    if not key_type:
        return jsonify({'error': 'Missing key type parameter.'}), 400
    if key_type not in ['symmetric', 'asymmetric']:
        return jsonify({'error': 'Invalid key type. Must be "symmetric" or "asymmetric".'}), 400
    try:
        #Get user for user id
        user = User.query.filter_by(username=current_user_username).first()
        if key_type == 'symmetric':
            # Retrieve symmetric key from database
            symmetric_key = SymmetricKey.query.filter_by(user_id=user.id).first()
            if symmetric_key:
                return jsonify({'key': symmetric_key.key}), 200
            else:
                return jsonify({'error': 'Symmetric key not found.'}), 404
        elif key_type == 'asymmetric':
            # Retrieve asymmetric keys from database
            asymmetric_key_pair = AsymmetricKeyPair.query.filter_by(user_id=user.id).first()
            if asymmetric_key_pair:
                return jsonify({
                    'private_key': asymmetric_key_pair.private_key,
                    'public_key': asymmetric_key_pair.public_key
                }), 200
            else:
                return jsonify({'error': 'Asymmetric keys not found.'}), 404
    except Exception as e:
        return jsonify({'error': f'Failed to retrieve key(s): {str(e)}'}), 500
    
@main.route('/user/register',methods=['POST'])
def create_user_route():
    #get user data
    username=request.json.get('username')
    password=request.json.get('password')
    #error handling
    if not username or not password:
        return jsonify({'Error':'Missing input.'}),400
    # Check if username already exists in the database
    if User.query.filter_by(username=username).first():
        return jsonify({'Error': 'Username already exists. Please choose a different username.'}), 400
    #create new user and store in db
    new_user = User(username=username)
    new_user.set_password(password)
    try:
        db.session.add(new_user)
        db.session.commit()
        return jsonify({'message': 'User created successfully'}), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': f'Failed to register user: {str(e)}'}), 500
    
@main.route('/user/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    user = User.query.filter_by(username=username).first()
    if user and user.check_password(password):
        access_token = create_access_token(identity=username)
        return jsonify(access_token=access_token), 200
    else:
        return jsonify({'error': 'Invalid username or password'}), 401