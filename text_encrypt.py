from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Util.Padding import pad, unpad

class DataEncryption:
    def __init__(self, key: bytes) -> None:
        self.key = key

    def encrypt(self, data: bytes):
        """
        :return: 32 bytes hashed key, 24 bytes iv, cipher
        """
        hash_object = SHA256.new(self.key)
        cipher = AES.new(pad(self.key, 16), AES.MODE_CBC)
        ct_bytes = cipher.encrypt(pad(data, AES.block_size))

        return hash_object.digest(), cipher.iv, ct_bytes
        
    def decrypt(self, data: bytes, iv: bytes):
        try:
            cipher = AES.new(pad(self.key, 16), AES.MODE_CBC, iv)
            pt = unpad(cipher.decrypt(data), AES.block_size)
            print("The message was: ", pt)
            return pt
        except (ValueError, KeyError):
            print("Incorrect decryption")
            return None