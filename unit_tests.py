import unittest
import requests
from base64 import b64encode
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from app.models import SymmetricKey, AsymmetricKeyPair
from app import create_app, db

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
        #get the hash from reponse
        self.hash_data=response.json()['hash_data']
    def test_verify_hash(self):
        #First, make sure the hash happened
        self.test_hash()
        #Send a post request to verify hash
        response=requests.post(BASE+"/hash",json={'data': self.data,'hash':self.hash_data})
        self.assertEqual(response.status_code,200)


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

#test the key generating function
class TestGenerateKeyAPI(unittest.TestCase):
    def test_generate_symmetric_key(self):
        response = requests.post(BASE+'/key/generate', json={'type': 'symmetric', 'algorithm': 'AES'})
        data = response.json()
        self.assertEqual(response.status_code, 200)
        self.assertIn('key', data)
        self.assertTrue(len(data['key']) > 0)
    def test_generate_asymmetric_key(self):
        response = requests.post(BASE+'/key/generate', json={'type': 'asymmetric', 'algorithm': 'RSA'})
        data = response.json()
        self.assertEqual(response.status_code, 200)
        self.assertIn('private_key', data)
        self.assertIn('public_key', data)
        self.assertTrue(len(data['private_key']) > 0)
        self.assertTrue(len(data['public_key']) > 0)
    def test_invalid_key_type(self):
        response = requests.post(BASE+'/key/generate', json={'type': 'invalid', 'algorithm': 'AES'})
        data = response.json()
        self.assertEqual(response.status_code, 400)
        self.assertIn('error', data)
        self.assertEqual(data['error'], 'Invalid key type. Must be "symmetric" or "asymmetric".')
    def test_invalid_algorithm_for_symmetric(self):
        response = requests.post(BASE+'/key/generate', json={'type': 'symmetric', 'algorithm': 'invalid'})
        data = response.json()
        self.assertEqual(response.status_code, 400)
        self.assertIn('error', data)
        self.assertEqual(data['error'], 'Invalid algorithm for symmetric key. Must be "AES".')
    def test_invalid_algorithm_for_asymmetric(self):
        response = requests.post(BASE+'/key/generate', json={'type': 'asymmetric', 'algorithm': 'invalid'})
        data = response.json()
        self.assertEqual(response.status_code, 400)
        self.assertIn('error', data)
        self.assertEqual(data['error'], 'Invalid algorithm for asymmetric key. Must be "RSA".')

#test key storage
class TestStoreKeyAPI(unittest.TestCase):
    def test_store_symmetric_key(self):
        key = b64encode(get_random_bytes(32)).decode('utf-8')
        payload = {
            'type': 'symmetric',
            'key': key
        }
        response = requests.post(BASE + '/key/store', json=payload)
        print(response.json())
        self.assertEqual(response.status_code, 201)
    '''
    def test_store_asymmetric_key(self):
        key = RSA.generate(2048) 
        private_key = b64encode(key.export_key()).decode('utf-8')
        public_key = b64encode(key.publickey().export_key()).decode('utf-8')
        payload = {
            'type': 'asymmetric',
            'key': {
                'public_key':public_key,
                'private_key':private_key,
            }
        }
        response = requests.post(BASE + '/key/store', json=payload)
        self.assertEqual(response.status_code, 201)
        '''
'''
#test user creation
class TestCreateUserAPI(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.username = "testuser"
        cls.password = "testpassword"
    def test_create_user_success(self):
        # Test case where user creation should succeed
        payload = {
            'username': self.username,
            'password': self.password
        }
        response = requests.post('/user/create', json=payload)
        self.assertEqual(response.status_code, 201)
    def test_create_user_missing_input(self):
        # Test case where required input is missing
        payload = {
            'username': self.username,
            # 'password': self.password  #simulate missing password
        }
        response =requests.post('/user/create', json=payload)
        self.assertEqual(response.status_code, 400)
        self.assertIn('Error', response.json)
        self.assertEqual(response.json['Error'], 'Missing input.')
    def test_create_user_existing_username(self):
        # Test case where username already exists in the database
        payload = {
            'username': self.username,
            'password': self.password 
        }
        # Create a user first
        response = requests.post('/user/create', json=payload)
        # Try to create a user with the same username again
        response = requests.post('/user/create', json=payload)
        self.assertEqual(response.status_code, 400)
        self.assertIn('Error', response.json)
        self.assertEqual(response.json['Error'], 'Username already exists. Please choose a different username.')
'''

if __name__ == '__main__':
    unittest.main()