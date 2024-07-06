# Crytography Services Restful API
**A restful API that provides cryptographic services such as: symmetric encryption and decryption, asymmetric encryption and decryption, hashing data, digitally signing data, digital signature verification, key storing and retreiving**
### Link: http://3.15.178.19:5000/
### The purpose of the project is to learn and practice concepts:
* Building a RESTful API.
* Strengthening knowledge on crypto services
* MVC Architectural Pattern.
### Following technologies and framework were used:
* Flask framework, flask blueprints pattern
* Flask-JWT- Extended for user authentication
* PyCrypto Library for encryption (AES,RSA), hashing(SHA256) and digital signatures(PKCS1)
* Werkzeug Web Server Gateway Interface
* SQLite relational database used as backend database
* HTTP (GET, POST, PUT, PATCH, DELETE, status codes)
* Postman for testing endpoints
### API Endpoints:
![API endpoints](https://github.com/minhtriet359/CryptoServiceAPI/assets/148809094/29b5001c-b034-4ea0-90a1-7e3628f69366)
### Sample Endpoints from Postman:
* Generate symmetric key:
![getkey](https://github.com/minhtriet359/CryptoServiceAPI/assets/148809094/536455fc-32f5-4835-aeea-d7eaa84ddf8e)
* Generate asymmetric key:
![getkey_asymmetric](https://github.com/minhtriet359/CryptoServiceAPI/assets/148809094/a83685ef-4ac1-4b3f-8473-8b2465f7d384)
* Symmetric Encryption:
![encrypt_symmetric](https://github.com/minhtriet359/CryptoServiceAPI/assets/148809094/bbee11f0-52d8-43be-b347-802f85bb4064)
* Symmetric Decryption:
![decrypt_symmetric](https://github.com/minhtriet359/CryptoServiceAPI/assets/148809094/81cfd4cc-9dcd-4d43-a775-a0c43529ce9c)
* Sign and verify signature:
![signature](https://github.com/minhtriet359/CryptoServiceAPI/assets/148809094/417375a0-6eaa-4bf5-af3c-7fcdc442dfe9)
![signature_verified](https://github.com/minhtriet359/CryptoServiceAPI/assets/148809094/55d20538-1db0-4015-890d-688b9cfc042b)
* User Register and Login:
(Note: Succesful login will generate a token)
![user_register](https://github.com/minhtriet359/CryptoServiceAPI/assets/148809094/457d748b-f028-4119-a38a-208f4879a139)
![user_login](https://github.com/minhtriet359/CryptoServiceAPI/assets/148809094/8254ea89-aa92-43a7-a8e6-b2af7f5f0a9a)
* Store and retreive keys
(Note: Token is required for authorization)
![token_required](https://github.com/minhtriet359/CryptoServiceAPI/assets/148809094/5b2d8e89-58b6-4ef0-9bee-902427a8f991)
![store_key](https://github.com/minhtriet359/CryptoServiceAPI/assets/148809094/2b53d95c-dda1-49d3-a9aa-3f434137a9e4)
![get_key_from_storage](https://github.com/minhtriet359/CryptoServiceAPI/assets/148809094/2e49f530-3f3d-4e01-8221-05e03f242f75)

### To activate virtual env on AWS for update:
source venv/bin/activate

