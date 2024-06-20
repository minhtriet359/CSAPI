from flask import Blueprint,request,jsonify
from .utils import (encrypt_symmetric,decrypt_symmetric)

main=Blueprint('main',__name__)

@main.route('/encrypt-symmetric', methods=['POST'])
def encrypt_symmetric_route():
    data=request.json.get('data')
    key=request.json.get('key')
    encrypted_data = encrypt_symmetric(data, key)
    return jsonify({'encrypted_data': encrypted_data})

@main.route('/decrypt-symmetric', methods=['POST'])
def decrypt_symmetric_route():
    data=request.json.get('data')
    key=request.json.get('key')
    decrypted_data = decrypt_symmetric(data, key)
    return jsonify({'decrypted_data': decrypted_data})