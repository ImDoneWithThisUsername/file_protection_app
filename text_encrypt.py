from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes, random

class DataEncryption:
    def __init__(self, key: bytes) -> None:
        self.key = key

    def addSalt(self, data: bytes):
        salt = get_random_bytes(random.randint(1,10)* 8)
        data = salt + ".".encode("utf-8") + data
        return data

    def splitSalt(self, data:bytes):
        pt_offset = data.find(".".encode("utf-8"))
        pt = data[pt_offset + 1:]
        return pt

    def encrypt(self, data: bytes):
        """
        :return: 32 bytes hashed key, 24 bytes iv, cipher
        """
        hash_object = SHA256.new(self.key)
        cipher = AES.new(pad(self.key, 16), AES.MODE_CBC)

        data = self.addSalt(data)
        ct_bytes = cipher.encrypt(pad(data, AES.block_size))

        return hash_object.digest(), cipher.iv, ct_bytes
        
    def decrypt(self, data: bytes, iv: bytes):
        try:
            cipher = AES.new(pad(self.key, 16), AES.MODE_CBC, iv)
            pt = unpad(cipher.decrypt(data), AES.block_size)

            pt = self.splitSalt(pt)
            return pt
        except (ValueError, KeyError):
            return None

if __name__ == "__main__":
    key = "test key".encode("utf-8")
    data = "test data".encode("utf-8")

    enc_obj = DataEncryption(key)
    hashed_key, iv, ct = enc_obj.encrypt(data)
    pt = enc_obj.decrypt(ct, iv)

    print(f"ct = {ct}")
    print(f"pt = {pt}")
    print("--------------------")
    pt = enc_obj.addSalt(data)
    print(pt)
    print(enc_obj.splitSalt(pt))

