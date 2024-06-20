from base64 import b64encode, b64decode
from Crypto.Cipher import AES, PKCS1_OAEP
import os
import json

#Encrypt data using symmetric private key
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

#Decrypt data using symmetric private key
def decrypt_symmetric(data,key):
    #decode the data using base 64 to get raw data
    raw_data=b64decode(data)
    #get nonce, tag and cipher text form raw data
    nonce,tag,ciphertext=raw_data[:16],raw_data[16:32],raw_data[32:]
    #Create AES cipher object using raw decoded binary key
    cipher=AES.new(b64decode(key),AES.MODE_GCM,nonce=nonce)
    #decrypt the data from cipher text to pain text
    return cipher.decrypt_and_verify(ciphertext,tag).decode('utf-8')
