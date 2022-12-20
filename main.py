from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes, random
class DataEncryption:
    key_size = 32
    iv_size = 16

    def __init__(self, key: bytes) -> None:
        self.key = key

    def addSalt(self, data: bytes) -> bytes:
        salt = get_random_bytes(random.randint(1,10)* 8)
        data = salt + ".".encode("utf-8") + data
        return data

    def splitSalt(self, data:bytes) -> bytes:
        pt_offset = data.find(".".encode("utf-8"))
        pt = data[pt_offset + 1:]
        return pt

    def compareHashed(self, hashed:bytes) -> bool:
        hash_object = SHA256.new(self.key)
        if (hash_object.digest() == hashed):
            return 1
        return 0

    def encrypt(self, data: bytes):
        """
        :return: 32 bytes hashed key, 24 bytes iv, cipher
        """
        hash_object = SHA256.new(self.key)
        cipher = AES.new(pad(self.key, 16), AES.MODE_CBC)

        data = self.addSalt(data)
        ct_bytes = cipher.encrypt(pad(data, AES.block_size))

        return hash_object.digest(), cipher.iv, ct_bytes
        
    def decrypt(self, data: bytes, iv: bytes) -> bytes:
        print(data)
        print(iv)
        print(self.key)
        try:
            cipher = AES.new(pad(self.key, 16), AES.MODE_CBC, iv)
            pt = unpad(cipher.decrypt(data), AES.block_size)

            pt = self.splitSalt(pt)
            return pt
        except (ValueError, KeyError):
            return None

class FileEncryption:
    def encrytion(self, filename: str, key: str):
        with open(filename,"rb") as file, open(filename+"1","wb") as f_out_1, open(filename+"2","wb") as f_out_2:
            pt = file.read()
            enc_object = DataEncryption(key.encode("utf-8"))

            hashed_key, iv, ct = enc_object.encrypt(pt)
            hashed_key = bytearray(hashed_key)
            iv = bytearray(iv)
            ct = bytearray(ct)

            data1 = hashed_key[:16] + iv[:8] + ct[:int(len(ct)/2)]
            data2 = hashed_key[16:] + iv[8:] + ct[int(len(ct)/2):]
            f_out_1.write(data1)
            f_out_2.write(data2)

    def decryption(self, filename1: str, filename2: str, key: str, filename_out:str):
        with open(filename1,"rb") as file_in_1, open(filename2, "rb") as file_in_2:
            data1 = file_in_1.read()
            data2 = file_in_2.read()
            enc_object = DataEncryption(key.encode("utf-8"))

            hashed_key = data1[:16] + data2[:16]
            iv = data1[16:16+8] + data2[16:16+8]
            ct = data1[16+8:] + data2[16+8:]

            if enc_object.compareHashed(hashed_key):

                pt = enc_object.decrypt(ct, iv)
                with open(filename_out, "wb") as f_out:
                    f_out.write(pt)



if __name__ == "__main__":
    
    file_in = "in.txt"
    file_out = "out.txt"
    key = "test key"
    hashed_key, iv, ct = None, None, None
    
    #encrypt a file
    with open(file_in, "rb") as f_in, open(file_out, "wb") as f_out:
        pt = f_in.read()
        enc_object = DataEncryption(key.encode("utf-8"))

        hashed_key, iv, ct = enc_object.encrypt(pt)
        print(hashed_key)
        print(iv)
        print(ct)
        data = hashed_key + iv + ct
        print("================")
        f_out.write(data)
    
    #decrypt a file
    with open(file_out, "rb") as f_in:
        hashed_key = f_in.read(32)
        iv = f_in.read(24)
        ct = f_in.read(32 + 24)

        print(hashed_key)
        print(iv)
        print(ct)
        pass

    obj_debug = True
    if obj_debug:
        f_method = FileEncryption()
        f_method.encrytion(file_in, key)
        f_method.decryption("in.txt1","in.txt2",key,"file_dec.txt")