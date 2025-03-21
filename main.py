import base64
import glob
import io
import logging
import os
import pathlib
import sys
import tkinter as tk
from tkinter import filedialog

import magic
import mutagen
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from dotenv import load_dotenv
from mutagen.easyid3 import ID3
from wasmer import Instance, Int32Array, Module, Store, Uint8Array, engine
from wasmer_compiler_cranelift import Compiler

from logging_config import setup_logger

# 加载 .env 文件
load_dotenv()

# 从环境变量获取配置
XM_KEY = os.getenv("XM_KEY", "ximalayaximalayaximalayaximalaya").encode()
OUTPUT_PATH = os.getenv("OUTPUT_PATH", "./output")
# 引入日志配置
logger = setup_logger(log_level=logging.INFO, log_file="./logs/xm_decrypt.log")


class XMInfo:
    def __init__(self):
        self.title = ""
        self.artist = ""
        self.album = ""
        self.tracknumber = 0
        self.size = 0
        self.header_size = 0
        self.ISRC = ""
        self.encodedby = ""
        self.encoding_technology = ""

    def iv(self):
        if self.ISRC != "":
            return bytes.fromhex(self.ISRC)
        return bytes.fromhex(self.encodedby)


def get_str(x):
    if x is None:
        return ""
    return x


def read_file(x):
    try:
        with open(x, "rb") as f:
            data = f.read()
            logger.info(f"读取文件 {x} 成功，共 {len(data)} 字节")
            return data
    except Exception as e:
        logger.error(f"读取文件 {x} 失败: {str(e)}")
        raise


# return number of id3 bytes
def get_xm_info(data: bytes):
    try:
        id3 = ID3(io.BytesIO(data), v2_version=3)
        id3value = XMInfo()
        id3value.title = str(id3["TIT2"])
        id3value.album = str(id3["TALB"])
        id3value.artist = str(id3["TPE1"])
        id3value.tracknumber = int(str(id3["TRCK"]))
        id3value.ISRC = "" if id3.get("TSRC") is None else str(id3["TSRC"])
        id3value.encodedby = "" if id3.get("TENC") is None else str(id3["TENC"])
        id3value.size = int(str(id3["TSIZ"]))
        id3value.header_size = id3.size
        id3value.encoding_technology = str(id3["TSSE"])
        logger.info(
            f"解析ID3信息成功，标题: {id3value.title}, 专辑: {id3value.album}, 艺术家: {id3value.artist}"
        )
        return id3value
    except Exception as e:
        logger.error(f"解析ID3信息失败: {str(e)}")
        raise


def get_printable_count(x: bytes):
    i = 0
    for i, c in enumerate(x):
        # all pritable
        if c < 0x20 or c > 0x7E:
            return i
    return i


def get_printable_bytes(x: bytes):
    return x[: get_printable_count(x)]


def xm_decrypt(raw_data):
    try:
        logger.info("加载 XM 解密模块")
        xm_encryptor = Instance(
            Module(
                Store(engine.Universal(Compiler)),
                pathlib.Path("./xm_encryptor.wasm").read_bytes(),
            )
        )
        xm_info = get_xm_info(raw_data)
        logger.info(f"解密文件，ID3头大小: {hex(xm_info.header_size)}")

        encrypted_data = raw_data[
            xm_info.header_size : xm_info.header_size + xm_info.size :
        ]

        # 使用环境变量中的解密密钥
        cipher = AES.new(XM_KEY, AES.MODE_CBC, xm_info.iv())
        de_data = cipher.decrypt(encrypted_data)
        de_data = get_printable_bytes(de_data)

        track_id = str(xm_info.tracknumber).encode()
        stack_pointer = xm_encryptor.exports.a(-16)
        de_data_offset = xm_encryptor.exports.c(len(de_data))
        track_id_offset = xm_encryptor.exports.c(len(track_id))

        memory_i = xm_encryptor.exports.i
        memview_unit8: Uint8Array = memory_i.uint8_view(offset=de_data_offset)
        for i, b in enumerate(de_data):
            memview_unit8[i] = b

        memview_unit8: Uint8Array = memory_i.uint8_view(offset=track_id_offset)
        for i, b in enumerate(track_id):
            memview_unit8[i] = b

        xm_encryptor.exports.g(
            stack_pointer, de_data_offset, len(de_data), track_id_offset, len(track_id)
        )

        memview_int32: Int32Array = memory_i.int32_view(offset=stack_pointer // 4)
        result_pointer = memview_int32[0]
        result_length = memview_int32[1]

        result_data = bytearray(memory_i.buffer)[
            result_pointer : result_pointer + result_length
        ].decode()
        decrypted_data = base64.b64decode(xm_info.encoding_technology + result_data)
        final_data = decrypted_data + raw_data[xm_info.header_size + xm_info.size :]
        logger.info("解密成功")
        return xm_info, final_data
    except Exception as e:
        logger.error(f"解密失败: {str(e)}")
        raise


def find_ext(data):
    try:
        exts = ["m4a", "mp3", "flac", "wav"]
        value = magic.from_buffer(data).lower()
        for ext in exts:
            if ext in value:
                logger.info(f"识别音频格式成功: {ext}")
                return ext
        raise Exception(f"未知格式 {value}")
    except Exception as e:
        logger.error(f"识别音频格式失败: {str(e)}")
        raise


def decrypt_xm_file(from_file):
    try:
        logger.info(f"开始解密文件: {from_file}")
        data = read_file(from_file)
        info, audio_data = xm_decrypt(data)
        output_dir = f"{OUTPUT_PATH}/{replace_invalid_chars(info.album)}"
        output = f"{output_dir}/{replace_invalid_chars(info.title)}.{find_ext(audio_data[:0xff])}"

        os.makedirs(output_dir, exist_ok=True)
        buffer = io.BytesIO(audio_data)
        tags = mutagen.File(buffer, easy=True)
        tags["title"] = info.title
        tags["album"] = info.album
        tags["artist"] = info.artist
        tags.save(buffer)

        with open(output, "wb") as f:
            buffer.seek(0)
            f.write(buffer.read())

        logger.info(f"解密成功，文件保存至: {output}")
    except Exception as e:
        logger.error(f"解密文件失败: {str(e)}")
        raise


def replace_invalid_chars(name):
    invalid_chars = ["/", "\\", ":", "*", "?", '"', "<", ">", "|"]
    for char in invalid_chars:
        if char in name:
            name = name.replace(char, " ")
    return name


def select_file():
    root = tk.Tk()
    root.withdraw()
    file_path = filedialog.askopenfilename()
    root.destroy()
    return file_path


def select_directory():
    root = tk.Tk()
    root.withdraw()
    directory_path = filedialog.askdirectory()
    root.destroy()
    return directory_path


if __name__ == "__main__":
    while True:
        print("欢迎使用喜马拉雅音频解密工具")
        print("本工具仅供学习交流使用，严禁用于商业用途")
        print("请选择您想要使用的功能：")
        print("1. 解密单个文件")
        print("2. 批量解密文件")
        print("3. 退出")
        choice = input()
        files_to_decrypt = []
        if choice == "1" or choice == "2":
            if choice == "1":
                files_to_decrypt = [select_file()]
                if files_to_decrypt == [""]:
                    print("检测到文件选择窗口被关闭")
                    continue
            elif choice == "2":
                dir_to_decrypt = select_directory()
                if dir_to_decrypt == "":
                    print("检测到目录选择窗口被关闭")
                    continue
                files_to_decrypt = glob.glob(os.path.join(dir_to_decrypt, "*.xm"))
            print(
                "请选择是否需要设置输出路径：（不设置默认为本程序目录下的output文件夹）"
            )
            print("1. 设置输出路径")
            print("2. 不设置输出路径")
            choice = input()
            if choice == "1":
                output_path = select_directory()
                if output_path == "":
                    print("检测到目录选择窗口被关闭")
                    continue
            elif choice == "2":
                output_path = "./output"
            for file in files_to_decrypt:
                decrypt_xm_file(file)
        elif choice == "3":
            sys.exit()
        else:
            print("输入错误，请重新输入！")
