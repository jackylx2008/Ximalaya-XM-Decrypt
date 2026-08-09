import base64
import io
import logging
import os
import sys
import traceback
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

import magic
from mutagen import File # type: ignore[attr-defined]
from mutagen.easyid3 import ID3 # type: ignore[attr-defined]
from Crypto.Cipher import AES
from dotenv import load_dotenv
from wasmtime import Store, Module, Instance, Engine

from logging_config import setup_logger

# 加载 .env 文件
load_dotenv()

# 从环境变量获取配置
XM_KEY = os.getenv("XM_KEY", "ximalayaximalayaximalayaximalaya").encode()
OUTPUT_PATH = os.getenv("OUTPUT_PATH", "./output")
INPUT_PATH = os.getenv("INPUT_PATH")
FOLDER_KEYWORD = os.getenv("FOLDER_KEYWORD", "").strip()
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


class WasmDecryptor:
    def __init__(self, wasm_path="./xm_encryptor.wasm"):
        logger.info("Loading XM Decryptor Module...")
        self.engine = Engine()
        self.module = Module.from_file(self.engine, wasm_path)

    def decrypt(self, de_data: bytes, track_id: bytes) -> str:
        store = Store(self.engine)
        instance = Instance(store, self.module, [])
        exports = instance.exports(store)

        a = exports["a"]
        c = exports["c"]
        g = exports["g"]
        memory_i = exports["i"]

        stack_pointer = a(store, -16) # type: ignore
        de_data_offset = c(store, len(de_data)) # type: ignore
        track_id_offset = c(store, len(track_id)) # type: ignore
        
        memory_i.write(store, de_data, de_data_offset) # type: ignore
        memory_i.write(store, track_id, track_id_offset) # type: ignore        
        g(
            store,
            stack_pointer,
            de_data_offset,
            len(de_data),
            track_id_offset,
            len(track_id),
        ) # type: ignore

        res_mem = memory_i.read(store, stack_pointer, stack_pointer + 8) # type: ignore
        result_pointer = int.from_bytes(res_mem[0:4], "little")
        result_length = int.from_bytes(res_mem[4:8], "little")

        return memory_i.read( # type: ignore
            store, result_pointer, result_pointer + result_length
        ).decode()


# Global instance
wasm_decryptor = None


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
        id3value.ISRC = "" if id3.get("TSRC") is None else str(id3["TSRC"]) # type: ignore   
        id3value.encodedby = "" if id3.get("TENC") is None else str(id3["TENC"])
        id3value.size = int(str(id3["TSIZ"]))
        id3value.header_size = id3.size
        id3value.encoding_technology = str(id3["TSSE"])
        logger.info(
            f"解析ID3信息成功，标题: {id3value.title}, "
            f"专辑: {id3value.album}, 艺术家: {id3value.artist}"
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
    global wasm_decryptor
    try:
        if wasm_decryptor is None:
            wasm_decryptor = WasmDecryptor()

        xm_info = get_xm_info(raw_data)
        logger.info(f"解密文件，ID3头大小: {hex(xm_info.header_size)}")

        encrypted_data = raw_data[
            xm_info.header_size : xm_info.header_size + xm_info.size
        ]

        # 使用环境变量中的解密密钥
        cipher = AES.new(XM_KEY, AES.MODE_CBC, xm_info.iv())
        de_data = cipher.decrypt(encrypted_data)
        de_data = get_printable_bytes(de_data)

        track_id = str(xm_info.tracknumber).encode()

        result_data = wasm_decryptor.decrypt(de_data, track_id)

        decrypted_data = base64.b64decode(xm_info.encoding_technology + result_data)
        final_data = decrypted_data + raw_data[xm_info.header_size + xm_info.size :]
        logger.info("解密成功")
        return xm_info, final_data
    except Exception as e:
        logger.error(f"解密失败: {str(e)}")
        logger.error(traceback.format_exc())
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


def decrypt_xm_file(from_file, output_path=OUTPUT_PATH):
    try:
        logger.info(f"开始解密文件: {from_file}")
        data = read_file(from_file)
        info, audio_data = xm_decrypt(data)
        output_dir = Path(output_path) / replace_invalid_chars(info.album)
        file_name = os.path.splitext(os.path.basename(from_file))[0]
        ext = find_ext(audio_data[:0xFF])
        output = output_dir / f"{file_name}.{ext}"

        os.makedirs(output_dir, exist_ok=True)
        buffer = io.BytesIO(audio_data)
        tags = File(buffer, easy=True)
        if tags:
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


def find_matching_directories(input_path, folder_keyword):
    """查找输入目录下名称包含关键字的一级子目录。"""
    keyword = folder_keyword.casefold()
    return sorted(
        (
            path
            for path in Path(input_path).iterdir()
            if path.is_dir() and keyword in path.name.casefold()
        ),
        key=lambda path: path.name.casefold(),
    )


def find_xm_files(directories):
    """递归收集所有匹配目录中的 .xm 文件。"""
    return sorted(
        (
            file_path
            for directory in directories
            for file_path in directory.rglob("*.xm")
            if file_path.is_file()
        ),
        key=lambda path: str(path).casefold(),
    )


@dataclass(frozen=True)
class BatchResult:
    matching_directories: int
    total_files: int
    succeeded: int
    failed: int


def process_batch(
    input_path: str | os.PathLike[str],
    output_path: str | os.PathLike[str],
    folder_keyword: str,
    progress_callback: Callable[[int, int, Path, bool | None], None] | None = None,
) -> BatchResult:
    """筛选目录并批量解密，可供命令行和图形界面共同调用。"""
    input_root = Path(input_path).expanduser() if input_path else None
    if input_root is None or not input_root.is_dir():
        raise ValueError(f"指定的输入目录不存在或未设置: {input_path}")

    keyword = folder_keyword.strip()
    if not keyword:
        raise ValueError("未设置文件夹关键字 FOLDER_KEYWORD")

    if not output_path:
        raise ValueError("未设置输出目录 OUTPUT_PATH")
    output_root = Path(output_path).expanduser()
    if output_root.exists() and not output_root.is_dir():
        raise ValueError(f"输出路径不是目录: {output_root}")
    output_root.mkdir(parents=True, exist_ok=True)

    matching_directories = find_matching_directories(input_root, keyword)
    if not matching_directories:
        logger.warning(
            f"在输入目录 {input_root} 下未找到名称包含 '{keyword}' 的文件夹"
        )
        return BatchResult(0, 0, 0, 0)

    logger.info(
        f"共找到 {len(matching_directories)} 个匹配文件夹: "
        + ", ".join(path.name for path in matching_directories)
    )

    xm_files = find_xm_files(matching_directories)
    if not xm_files:
        logger.warning("未在匹配的文件夹中找到 .xm 文件")
        return BatchResult(len(matching_directories), 0, 0, 0)

    logger.info(f"共找到 {len(xm_files)} 个 .xm 文件，开始解密处理...")
    succeeded = 0
    failed = 0
    for index, file_path in enumerate(xm_files, start=1):
        success = False
        if progress_callback:
            progress_callback(index - 1, len(xm_files), file_path, None)
        try:
            decrypt_xm_file(file_path, output_root)
            succeeded += 1
            success = True
        except Exception as exc:
            failed += 1
            logger.error(f"处理文件 {file_path} 时发生错误: {exc}")
        finally:
            if progress_callback:
                progress_callback(index, len(xm_files), file_path, success)

    logger.info(f"所有文件处理完成：成功 {succeeded}，失败 {failed}。")
    return BatchResult(
        len(matching_directories), len(xm_files), succeeded, failed
    )


def main() -> int:
    """使用 .env 配置运行命令行批处理。"""
    try:
        process_batch(INPUT_PATH or "", OUTPUT_PATH, FOLDER_KEYWORD)
    except ValueError as exc:
        logger.error(str(exc))
        return 1
    return 0


def launch_gui() -> None:
    """启动桌面图形界面。"""
    from ui import launch_ui

    launch_ui(
        process_batch=process_batch,
        default_input=INPUT_PATH or "",
        default_output=OUTPUT_PATH,
        default_keyword=FOLDER_KEYWORD,
    )


if __name__ == "__main__":
    if "--cli" in sys.argv[1:]:
        raise SystemExit(main())
    launch_gui()
