import requests
from base64 import b64encode, b64decode
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes


BASE="http://127.0.0.1:5000/"

#data={'name:':'Triet','age':28}
data="abcd"
key=b64encode(get_random_bytes(32)).decode('utf-8')
print("key:",key)

en_response=requests.post(BASE+"/encrypt-symmetric",json={'data': data, 'key': key})
print(en_response.json())
data=en_response.json()['encrypted_data']
print(data)

input()

de_response=requests.post(BASE+"/decrypt-symmetric",json={'data': data, 'key': key})
print(de_response.json())