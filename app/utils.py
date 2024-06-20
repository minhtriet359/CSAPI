from base64 import b64encode, b64decode
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
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


