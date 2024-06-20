import requests
from base64 import b64encode, b64decode
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes


BASE="http://127.0.0.1:5000/"

data={'name:':'Triet','age':28}

key=RSA.generate(2048)
private_key=b64encode(key.export_key()).decode('utf-8')
public_key=b64encode(key.publickey().export_key()).decode('utf-8')

en_response=requests.post(BASE+"/encrypt-asymmetric",json={'data': data, 'key': public_key})
print(en_response.json())
data=en_response.json()['encrypted_data']
print(data)

input()

de_response=requests.post(BASE+"/decrypt-asymmetric",json={'data': data, 'key': private_key})
print(de_response.json())