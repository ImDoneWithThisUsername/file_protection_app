import os
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes, random
import ctypes


def hide_folder(path:str):
    FILE_ATTRIBUTE_HIDDEN = 0x02

    ret = ctypes.windll.kernel32.SetFileAttributesW(path,
                                                    FILE_ATTRIBUTE_HIDDEN)
    if ret:
        return
    else:  # return code of zero indicates failure -- raise a Windows error
        raise ctypes.WinError()
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
        try:
            cipher = AES.new(pad(self.key, 16), AES.MODE_CBC, iv)
            pt = unpad(cipher.decrypt(data), AES.block_size)

            pt = self.splitSalt(pt)
            return pt
        except (ValueError, KeyError):
            return None

class FileEncryption:
    def encrytion(self, path: str, key: str, path1: str, path2: str):
        filename = os.path.basename(path)
        file1_path = os.path.join(path1,filename+"1")
        file2_path = os.path.join(path2,filename+"2")
        with open(path,"rb") as file, open(file1_path,"wb") as f_out_1, open(file2_path,"wb") as f_out_2:
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
        # Close file
        file.close()
        f_out_1.close()
        f_out_2.close()
        # Hide directory
        hide_folder(path1)
        hide_folder(path2)

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
                f_out.close()
        file_in_1.close()
        file_in_2.close()
