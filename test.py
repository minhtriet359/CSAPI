import requests
from base64 import b64encode, b64decode
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes


BASE="http://127.0.0.1:5000/"

data={'name:':'Triet','age':28}
#data='abcd'
algorithm='sha-256'

en_response=requests.post(BASE+"/hash",json={'data': data})
print(en_response.json())
data=en_response.json().get('hash_data')
print(data)
