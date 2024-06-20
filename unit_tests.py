import unittest
import requests
from base64 import b64encode
from Crypto.Random import get_random_bytes

BASE = "http://127.0.0.1:5000/"

class TestSymmetricEncryptionAPI(unittest.TestCase):

    @classmethod
    def setUp(cls):
        # Generate a random AES key and encode it to base64
        cls.key = b64encode(get_random_bytes(32)).decode('utf-8')
        cls.data = "abcd0124@"
        print("key:", cls.key)

    def test_encrypt_symmetric(self):
        # Send a POST request to encrypt the data
        response = requests.post(BASE + "/encrypt-symmetric", json={'data': self.data, 'key': self.key})
        self.assertEqual(response.status_code, 200)
        response_data = response.json()
        self.assertIn('encrypted_data', response_data)
        self.encrypted_data = response_data['encrypted_data']
        print("Encrypted data:", self.encrypted_data)

    def test_decrypt_symmetric(self):
        # First, ensure encryption has happened
        self.test_encrypt_symmetric()
        
        # Send a POST request to decrypt the data
        response = requests.post(BASE + "/decrypt-symmetric", json={'data': self.encrypted_data, 'key': self.key})
        self.assertEqual(response.status_code, 200)
        response_data = response.json()
        self.assertIn('decrypted_data', response_data)
        decrypted_data = response_data['decrypted_data']
        print("Decrypted data:", decrypted_data)

        # Check if the decrypted data matches the original data
        self.assertEqual(decrypted_data, self.data)

if __name__ == '__main__':
    unittest.main()