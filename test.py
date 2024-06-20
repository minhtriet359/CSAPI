import requests
from base64 import b64encode, b64decode
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes


BASE="http://127.0.0.1:5000/"

#data={'name:':'Triet','age':28}
data='abcd'
key=RSA.generate(2048)
private_key=b64encode(key.export_key()).decode('utf-8')
public_key=b64encode(key.publickey().export_key()).decode('utf-8')

response=requests.post(BASE+"/sign",json={'data': data,'key':private_key})
print(response.json())
signature=response.json().get('signature')
print(signature)

response=requests.post(BASE+"/verify",json={'data': data,'signature':signature,'key':public_key})
print(response.json())
#data=response.json().get('signature')