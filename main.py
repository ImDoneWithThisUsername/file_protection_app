from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes, random
import ctypes
import _thread
import threading
import os

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
        file.close()
        f_out_1.close()
        f_out_2.close()

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

class DynamicPassword:
    keywords = {
        "1": "cat",
        "2": "dog",
        "3": "fish",
        "4": "bird",
        "5": "tiger",
        "6": "lion",
        "7": "rat",
        "8": "ant",
        "9": "cow",
        "0": "fox"
    }
    dpwd = None
    time_out = 5

    def __init__(self) -> None:
        self.dpwd = ""
        for _ in range(0,6):
            self.dpwd += str(random.randint(0,9))

    def compare_dpwd(self, input_pwd:str) -> bool:
        res = ""
        for num in self.dpwd:
            res += self.keywords[num]
        if res == input_pwd:
            return 1
        return 0

def raw_input_with_timeout(prompt, timeout=3*60.0):
    timer = threading.Timer(timeout, _thread.interrupt_main)
    astring = None
    try:
        timer.start()
        astring = input(prompt)
    except KeyboardInterrupt:
        pass
    timer.cancel()
    return astring

def hide_folder(path:str):
    FILE_ATTRIBUTE_HIDDEN = 0x02

    ret = ctypes.windll.kernel32.SetFileAttributesW(path,
                                                    FILE_ATTRIBUTE_HIDDEN)
    if ret:
        print('attribute set to Hidden')
    else:  # return code of zero indicates failure -- raise a Windows error
        raise ctypes.WinError()



if __name__ == "__main__":
    """
    Here come the program
    """
    dpwd_obj = DynamicPassword()
    ip = raw_input_with_timeout(f"Nhập mật khẩu động trong 3 phút (code: {dpwd_obj.dpwd}): ")
    if ip == None:
        print("Đã quá thời gian")
    else:
        if dpwd_obj.compare_dpwd(ip) == 0:
            print("Sai mật khẩu động ")
            exit()
        choice = input("1/ Mã hóa file \n"
                       "2/ Giải mã file \n"
                       "Chọn chức năng (Enter để thoát): ")
        if choice == "1":
            # encryption
            path = input("Nhập đường dẫn kèm tên file cần được mã hóa: ")
            key = input("Nhập mật khẩu mã hóa file: ")
            print("File được tách thành 2 file nhỏ.")
            path1 = input("Nhập đường dẫn nơi lưu file 1: ")
            path2 = input("Nhập đường dẫn nơi lưu file 2: ")
            f_enc_obj = FileEncryption()
            f_enc_obj.encrytion(path, key, path1, path2)
            print("Mã hóa file thành công.")
        
        elif choice == "2":
            # decryption
            path1 = input("Nhập đường dẫn kèm tên file thứ 1: ")
            path2 = input("Nhập đường dẫn kèm tên file thứ 2: ")
            f_enc_obj = FileEncryption()
            f_out = input("Nhập đường dẫn kèm tên file output: ")
            key = input("Nhập mật khẩu mã hóa file: ")
            f_enc_obj.decryption(path1, path2, key, f_out)
            print("Giải mã file thành công.")
        else:
            exit()

    # test_timeout = True
    # if test_timeout:
    #     dpwd_obj = DynamicPassword()
    #     ip = raw_input_with_timeout(f"Nhập mật khẩu động trong 3 phút (code: {dpwd_obj.dpwd}): ")
    #     if ip == None:
    #         print("Đã quá thời gian")
    #     else:
    #         if dpwd_obj.compare_dpwd(ip):
    #             print("oke")
    #         else:
    #             print("Sai mật khẩu động ")


    # file_in = "in.txt"
    # file_out = "out.txt"
    # key = "test key"
    # hashed_key, iv, ct = None, None, None
    
    # test_enc_file = False
    # if test_enc_file:
    #     #encrypt a file
    #     with open(file_in, "rb") as f_in, open(file_out, "wb") as f_out:
    #         pt = f_in.read()
    #         enc_object = DataEncryption(key.encode("utf-8"))

    #         hashed_key, iv, ct = enc_object.encrypt(pt)
    #         print(hashed_key)
    #         print(iv)
    #         print(ct)
    #         data = hashed_key + iv + ct
    #         print("================")
    #         f_out.write(data)
        
    #     #decrypt a file
    #     with open(file_out, "rb") as f_in:
    #         hashed_key = f_in.read(32)
    #         iv = f_in.read(24)
    #         ct = f_in.read(32 + 24)

    #         print(hashed_key)
    #         print(iv)
    #         print(ct)
    #         pass

    # obj_debug = False
    # if obj_debug:
    #     f_method = FileEncryption()
    #     f_method.encrytion(file_in, key)
    #     f_method.decryption("in.txt1","in.txt2",key,"file_dec.txt")

    # hide_folder_debug = False
    # if hide_folder_debug:
    #     hide_folder("D:\\ky-1-nam-4\\data-security-and-recovery\\final\\test")

    # test_dpwd = True
    # if test_dpwd:
    #     dpwd_obj = DynamicPassword()
    #     print(dpwd_obj.dpwd)
    #     usr_ans = input()
    #     print(dpwd_obj.compare_dpwd(usr_ans))
