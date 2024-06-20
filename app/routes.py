from flask import Blueprint,request,jsonify
from .utils import (encrypt_symmetric,decrypt_symmetric,encrypt_asymmetric,decrypt_asymmetric,sign_data,verify_signature)

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