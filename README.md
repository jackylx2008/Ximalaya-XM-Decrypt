# 喜马拉雅 XM 文件解密工具

一个用于批量解密喜马拉雅 `.xm` 音频文件的命令行工具。程序可以根据文件夹名称关键字筛选需要处理的专辑目录，并将解密后的音频按专辑名输出。

## 功能

- 从 `INPUT_PATH` 的一级子目录中，筛选名称包含 `FOLDER_KEYWORD` 的所有目录。
- 递归搜索命中目录内的 `.xm` 文件并批量解密。
- 自动识别 `m4a`、`mp3`、`flac` 和 `wav` 格式。
- 写入标题、专辑和艺术家等音频标签。
- 将文件输出到 `OUTPUT_PATH/<专辑名>/`，并记录处理日志。
- 单个文件处理失败时继续处理其余文件。

## 环境要求

- Python 3.8 或更高版本
- `xm_encryptor.wasm` 位于项目根目录

## 安装

```bash
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

macOS/Linux 下激活虚拟环境时使用：

```bash
source .venv/bin/activate
```

## 配置

复制 `.env.example` 为 `.env`，然后修改配置：

```dotenv
XM_KEY=ximalayaximalayaximalayaximalaya
INPUT_PATH=D:\path\to\ximalaya-downloads
FOLDER_KEYWORD=神探迈克狐
OUTPUT_PATH=D:\path\to\output
```

| 配置项 | 说明 |
| --- | --- |
| `XM_KEY` | XM 文件的 AES 解密密钥；未设置时使用项目默认值 |
| `INPUT_PATH` | 包含多个专辑文件夹的父目录，必填 |
| `FOLDER_KEYWORD` | 一级子目录名称关键字，必填；匹配英文时不区分大小写 |
| `OUTPUT_PATH` | 解密文件的根输出目录；默认为 `./output` |

例如，当输入目录为：

```text
ximalaya-downloads/
├── 神探迈克狐·国际学院1/
├── 神探迈克狐·国际学院2/
└── 其他专辑/
```

配置 `FOLDER_KEYWORD=神探迈克狐` 后，程序会递归处理前两个目录，忽略“其他专辑”。

## 运行

```bash
python main.py
```

处理日志会同时输出到终端和 `logs/xm_decrypt.log`。如果输入目录、文件夹关键字或匹配文件存在问题，程序会在日志中给出对应提示。

## 输出结构

```text
OUTPUT_PATH/
└── <专辑名>/
    ├── 001.mp3
    └── 002.m4a
```

专辑名中不适合 Windows 文件名的字符会被替换为空格。

## 项目文件

- `main.py`：配置读取、目录筛选、XM 解密和音频输出。
- `logging_config.py`：日志配置。
- `xm_encryptor.wasm`：XM 解密所需的 WebAssembly 模块。

## 说明

本工具参考了 [@aynakeya 的喜马拉雅 XM 文件解密分析](https://www.aynakeya.com/2023/03/15/ctf/xi-ma-la-ya-xm-wen-jian-jie-mi-ni-xiang-fen-xi/)。请仅处理自己合法获取并有权使用的音频文件。
