from base64 import b64encode, b64decode
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15
import os
import json

#Encrypt plain text data using symmetric private key
def encrypt_symmetric(data,key):
    #Serialzie the dictionary type data into a json formatted string
    if(isinstance(data,dict)):
        data=json.dumps(data)
    #Create AES cipher object using raw decoded binary key
    cipher=AES.new(b64decode(key),AES.MODE_GCM)
    #encrypt plaintext data and generate an authentication tag
    ciphertext,tag=cipher.encrypt_and_digest(data.encode('utf-8'))
    #combining ciphertext, nonce and tag and produce a string using base64 encode and decode to UTF-8 and return
    return b64encode(cipher.nonce+tag+ciphertext).decode('utf-8')

#Decrypt encrypted data using symmetric private key
def decrypt_symmetric(data,key):
    #decode the data using base 64 to get raw data
    raw_data=b64decode(data)
    #get nonce, tag and cipher text form raw data
    nonce,tag,ciphertext=raw_data[:16],raw_data[16:32],raw_data[32:]
    #Create AES cipher object using raw decoded binary key
    cipher=AES.new(b64decode(key),AES.MODE_GCM,nonce=nonce)
    #decrypt the data from cipher text to pain text
    return cipher.decrypt_and_verify(ciphertext,tag).decode('utf-8')

#Encrypt plain text data using asymmetric public key
def encrypt_asymmetric(data,public_key):
    #Serialzie the dictionary type data into a json formatted string
    if(isinstance(data,dict)):
        data=json.dumps(data)
    #decode public key into binary form
    key=RSA.import_key(b64decode(public_key))
    #create cipher object from key using OAEP
    cipher=PKCS1_OAEP.new(key)
    #encryp and return the data
    return b64encode(cipher.encrypt(data.encode('utf-8'))).decode('utf-8')

#Decrypt encrypted data using asymmetric private key
def decrypt_asymmetric(data,private_key):
    #decode private key into binary form
    key=RSA.import_key(b64decode(private_key))
    #get cipher object from key using OAEP
    cipher=PKCS1_OAEP.new(key)
    #decrypt and return the data
    return cipher.decrypt(b64decode(data)).decode('utf-8')

#Hash data using sha256 hash function
def hash(data,algorithm='sha256'):
    if algorithm.lower()=='sha256':
        hash_object=SHA256.new(data.encode('utf-8'))
        return hash_object.hexdigest()
    else:
        return f"Error: Unsupported algorithm '{algorithm}'. Please use 'sha256'."


#Sign data with digital signature using private key
def sign_data(data,private_key):
    #decode the base64-encoded private key and imports it as an RSA private key object
    key=RSA.import_key(b64decode(private_key))
    #create a new SHA-256 hash object and hashes the input data
    hash_object=SHA256.new(data.encode('utf-8'))
    #signing the hash data
    signature=pkcs1_15.new(key).sign(hash_object)
    #encode and return the signature
    return b64encode(signature).decode('utf-8')

#Verify signature using public key
def verify_signature(data, signature, public_key):
    #decode the base64-encoded public key and imports it as an RSA public key object
    key = RSA.import_key(b64decode(public_key))
    #create a new SHA-256 hash object and hashes the input data
    hash_object = SHA256.new(data.encode('utf-8'))
    #Verify the signature
    try:
        pkcs1_15.new(key).verify(hash_object, b64decode(signature))
        return True
    except (ValueError, TypeError):
        return False

#generate symmetric and asymmetric keys
def generate_key(type='symmetric', algorithm='AES'):
    #generate a symmetric key using AES-256 algorithm
    if type == 'symmetric' and algorithm == 'AES':
        key = os.urandom(32)  #generate a 256-bit (32-byte) random key
        return b64encode(key).decode('utf-8')  #encode the key in base64 and return as a string
    #generate asymmetric keys using RSA algorithm
    elif type == 'asymmetric' and algorithm == 'RSA':
        key = RSA.generate(2048)  #generate an 2048 bit RSA key pair
        private_key = b64encode(key.export_key()).decode('utf-8')  #export and encode private key in base64
        public_key = b64encode(key.publickey().export_key()).decode('utf-8')  #export and encode public key in base64
        return private_key, public_key  #return private key and public key pair
