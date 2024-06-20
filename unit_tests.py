import unittest
import requests
from base64 import b64encode
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256

BASE = "http://127.0.0.1:5000/"


#Test symmetric key functions
class TestSymmetricEncryptionAPI(unittest.TestCase):
    @classmethod
    def setUp(cls):
        #Generate a random AES key and encode it to base64
        cls.key = b64encode(get_random_bytes(32)).decode('utf-8')
        cls.data = "abcd0124@"
    def test_encrypt_symmetric(self):
        #Send a POST request to encrypt the data
        response = requests.post(BASE + "/encrypt-symmetric", json={'data': self.data, 'key': self.key})
        self.assertEqual(response.status_code, 200)
        response_data = response.json()
        self.assertIn('encrypted_data', response_data)
        self.encrypted_data = response_data['encrypted_data']
    def test_decrypt_symmetric(self):
        #First, ensure encryption has happened
        self.test_encrypt_symmetric()
        
        #Send a POST request to decrypt the data
        response = requests.post(BASE + "/decrypt-symmetric", json={'data': self.encrypted_data, 'key': self.key})
        self.assertEqual(response.status_code, 200)
        response_data = response.json()
        self.assertIn('decrypted_data', response_data)
        decrypted_data = response_data['decrypted_data']

        #Check if the decrypted data matches the original data
        self.assertEqual(decrypted_data, self.data)


#test asymmetric key functions
class TestASymmetricEncryptionAPI(unittest.TestCase):
    @classmethod
    def setUp(cls):
        #Generate a random AES key and encode it to base64
        key=RSA.generate(2048)
        cls.private_key=b64encode(key.export_key()).decode('utf-8')
        cls.public_key=b64encode(key.publickey().export_key()).decode('utf-8')
        cls.data = "abcd0124@"
    def test_encrypt_asymmetric(self):
        #Send a POST request to encrypt the data
        response = requests.post(BASE + "/encrypt-asymmetric", json={'data': self.data, 'key': self.public_key})
        self.assertEqual(response.status_code, 200)
        response_data = response.json()
        self.assertIn('encrypted_data', response_data)
        self.encrypted_data = response_data['encrypted_data']
    def test_decrypt_asymmetric(self):
        #First, ensure encryption has happened
        self.test_encrypt_asymmetric()  
        #Send a POST request to decrypt the data
        response = requests.post(BASE + "/decrypt-asymmetric", json={'data': self.encrypted_data, 'key': self.private_key})
        self.assertEqual(response.status_code, 200)
        response_data = response.json()
        self.assertIn('decrypted_data', response_data)
        decrypted_data = response_data['decrypted_data']
        #Check if the decrypted data matches the original data
        self.assertEqual(decrypted_data, self.data)


#test hash functions
class TestHashAPI(unittest.TestCase):
    @classmethod
    def setUp(cls):
        cls.data = "abcd0124@"
    def test_hash(self):
        #Send a post request to hash the data
        response=requests.post(BASE+"/hash",json={'data': self.data})
        self.assertEqual(response.status_code, 200) #Ensure request was successful


#test digital signature functions
class TestDigitalSignatureAPI(unittest.TestCase):
    @classmethod
    def setUp(cls):
        #Generate a random AES key and encode it to base64
        key=RSA.generate(2048)
        cls.private_key=b64encode(key.export_key()).decode('utf-8')
        cls.public_key=b64encode(key.publickey().export_key()).decode('utf-8')
        cls.data = "abcd0124@"
    def test_digital_signature(self):
        #Send a POST request to encrypt the data
        response=requests.post(BASE+"/sign",json={'data': self.data,'key':self.private_key})
        #Ensure request was successful
        self.assertEqual(response.status_code, 200)
        #get signature from response
        self.signature=response.json().get('signature')
    def test_verify_signature(self):
        #First, ensure encryption has happened
        self.test_digital_signature()
        #Send a POST request to decrypt the data
        response = requests.post(BASE + "/verify-signature", json={'data': self.data,'signature':self.signature, 'key': self.public_key})
        self.assertEqual(response.status_code, 200)
        

if __name__ == '__main__':
    unittest.main()