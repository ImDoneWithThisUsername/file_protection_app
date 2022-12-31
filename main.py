from Crypto.Random import random
import _thread
import threading
import os
import inspect
import sys

letter = input("Nhập đường dẫn USB chứa phần còn lại của chương trình (Để trống nếu không có): ")
if letter != "":
    path = letter + ":\\"   # USB path of other modules
    sys.path.append(path)

from main_usb import DataEncryption, FileEncryption

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

    def check_dpwd(self) -> None:
        self.wrong_count = 0
        while 1:
            ip = raw_input_with_timeout(f"Nhập mật khẩu động trong 3 phút (code: {dpwd_obj.dpwd}): ")
            if ip == None:
                print("Đã quá thời gian")
            else:
                if dpwd_obj.compare_dpwd(ip) == 0:
                    self.wrong_count += 1
                    if self.wrong_count >= 3:
                        self_delete()
                        exit()
                    print("Sai mật khẩu động {} lần, sai 3 lần chương trình sẽ tự hủy.".format(self.wrong_count))
                else:
                    return
        
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

def self_delete():
    os.remove(__file__)
    usb = inspect.getfile(DataEncryption)
    os.remove(usb)
    print("Chương trình đã tự hủy!")    

if __name__ == "__main__":
    dpwd_obj = DynamicPassword()
    dpwd_obj.check_dpwd()
        
    while 1:
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
            print("Mã hóa file thành công, nơi chứa file đã được ẩn đi.")
        
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
