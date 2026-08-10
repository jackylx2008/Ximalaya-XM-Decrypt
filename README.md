# 喜马拉雅 XM 文件解密工具

一个用于批量解密喜马拉雅 `.xm` 音频文件的桌面与命令行工具。程序可以根据文件夹名称关键字筛选需要处理的专辑目录，并将解密后的音频按专辑名输出。

## 功能

- 提供桌面 UI，输入和输出目录支持直接输入、粘贴或通过系统资源管理器选择。
- 后台执行批量解码，并在界面中显示实时日志；底部状态栏实时显示文件总数、处理进度和当前文件。
- 可选择是否按文件夹关键词筛选；不启用筛选时递归处理整个输入目录。
- 启用筛选时，从 `INPUT_PATH` 的一级子目录中筛选名称包含 `FOLDER_KEYWORD` 的所有目录。
- 递归搜索命中目录内的 `.xm` 文件并批量解密。
- 自动识别 `m4a`、`mp3`、`flac` 和 `wav` 格式。
- 写入标题、专辑和艺术家等音频标签。
- 将文件输出到 `OUTPUT_PATH/<专辑名>/`，并记录处理日志。
- 单个文件处理失败时继续处理其余文件。

## 环境要求

- Python 3.10 或更高版本
- `xm_encryptor.wasm` 位于项目根目录

## 安装

### 项目本地 Conda 环境（推荐）

项目使用 `environment.yml` 统一 Python 3.12、Tk 和解码依赖。建议在项目根目录创建 `.conda`，使不同项目的依赖互不影响。

Windows 11 PowerShell：

```powershell
conda env create --prefix .\.conda -f environment.yml
conda activate .\.conda
python main.py
```

macOS/Linux：

```bash
conda env create --prefix ./.conda -f environment.yml
conda activate ./.conda
python main.py
```

如果不想激活环境，可以直接使用环境内的 Python：

```powershell
# Windows
.\.conda\python.exe main.py
```

```bash
# macOS/Linux
./.conda/bin/python main.py
```

环境已经存在时，通过相同的 `environment.yml` 同步依赖：

```bash
conda env update --prefix ./.conda -f environment.yml --prune
```

可以通过以下命令检查 Python、Tk 和主要依赖：

```bash
conda run --prefix ./.conda python --version
conda run --prefix ./.conda python -c "import tkinter, mutagen, Crypto, dotenv, wasmtime; print('environment OK')"
```

### 跨平台兼容性说明

- `.conda` 中包含当前操作系统和 CPU 平台对应的二进制文件，不能在 Windows、macOS 和 Linux 之间直接复制使用。
- `.conda/` 已加入 `.gitignore`；CloudStation 或 Git 只需同步源码、`environment.yml` 和 `requirements.txt`。
- 在每台新电脑或每个操作系统上进入项目根目录，重新执行对应平台的 `conda env create --prefix ...` 命令。
- `environment.yml` 由 Conda 安装 Python 3.12 和 Tk，再通过 pip 安装其余跨平台依赖。
- 输入和输出目录使用各平台自己的 `.env` 配置或程序自动解析的平台默认路径。

如果 PowerShell 无法识别 `conda activate`，先执行下面的命令并重新打开 PowerShell：

```powershell
conda init powershell
```

### Python venv 备选方案

也可以使用 Python 自带的虚拟环境：

```bash
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

macOS/Linux 下激活虚拟环境时使用：

```bash
source .venv/bin/activate
```

使用 Homebrew Python 且遇到 `No module named '_tkinter'` 的 macOS 用户，还需要安装与 Python 版本对应的 Tk：

```bash
brew install python-tk@3.14
```

可以通过 `python3 --version` 查看当前 Python 版本，并相应调整公式中的版本号。
也可以使用自带 Tk 的 macOS 系统 Python 创建虚拟环境：

```bash
/usr/bin/python3 -m venv .venv
```

## 配置

复制 `.env.example` 为 `.env`，然后修改配置：

```dotenv
XM_KEY=ximalayaximalayaximalayaximalaya
# 以下配置均为可选覆盖项
# CLOUDSTATION_ROOT=/path/to/cloudstation
# INPUT_PATH=/path/to/ximalaya-downloads
# OUTPUT_PATH=/path/to/output
FOLDER_KEYWORD=example
```

| 配置项 | 说明 |
| --- | --- |
| `XM_KEY` | XM 文件的 AES 解密密钥；未设置时使用项目默认值 |
| `CLOUDSTATION_ROOT` | 可选；CloudStation 根目录，优先于平台专用变量 |
| `CLOUDSTATION_ROOT_WINDOWS` | 可选；Windows CloudStation 根目录 |
| `CLOUDSTATION_ROOT_MACOS` | 可选；macOS CloudStation 根目录 |
| `CLOUDSTATION_ROOT_LINUX` | 可选；Linux CloudStation 根目录 |
| `INPUT_PATH` | 可选；包含多个专辑文件夹的父目录，优先于平台默认值 |
| `FOLDER_KEYWORD` | 可选；一级子目录名称关键字，匹配英文时不区分大小写；留空时处理整个输入目录 |
| `OUTPUT_PATH` | 可选；解密文件的根输出目录，默认使用当前用户桌面 |

未设置路径变量时，程序使用以下平台默认值：

- macOS 输入目录：`~/SynologyDrive/有声书/ximalaya-xm/`
- Windows 输入目录：`D:\CloudStation\有声书\ximalaya-xm\`
- macOS 输出目录：当前用户的 `~/Desktop` 目录
- Windows 输出目录：当前用户的 `C:\Users\<用户>\OneDrive\Desktop` 目录

单击输入目录右侧的“浏览…”时，目录选择器会从当前输入目录打开，展示其下的专辑子目录。

例如，当输入目录为：

```text
ximalaya-downloads/
├── 神探迈克狐·国际学院1/
├── 神探迈克狐·国际学院2/
└── 其他专辑/
```

配置 `FOLDER_KEYWORD=神探迈克狐` 后，程序会递归处理前两个目录，忽略“其他专辑”。

## 运行桌面界面

```bash
python main.py
```

界面启动后：

1. 在“输入目录”和“输出目录”文本框中直接输入或粘贴路径，或者单击“浏览…”通过系统资源管理器选择目录。
2. 如需只处理特定专辑，勾选“按文件夹关键词筛选”并填写关键字；不勾选时会处理整个输入目录。
3. 单击“开始解码”，在进度条和处理日志区域查看执行状态。

解码期间界面会保持响应；为避免文件写入中断，任务完成前不能直接关闭窗口。

## 命令行模式

如需完全使用 `.env` 中的配置运行，可添加 `--cli`：

```bash
python main.py --cli
```

处理日志会同时输出到终端和 `logs/xm_decrypt.log`。如果输入目录、文件夹关键字或匹配文件存在问题，程序会在日志中给出对应提示。

## 测试

```bash
python -m unittest discover -s tests -v
```

## 输出结构

```text
OUTPUT_PATH/
└── <专辑名>/
    ├── 001.mp3
    └── 002.m4a
```

专辑名中不适合 Windows 文件名的字符会被替换为空格。

## 项目文件

- `main.py`：配置读取、目录筛选、批处理、XM 解密和音频输出。
- `ui.py`：Tkinter 桌面界面、资源管理器目录选择、进度和日志显示。
- `logging_config.py`：日志配置。
- `path_config.py`：跨平台输入、输出和 CloudStation 默认路径解析。
- `environment.yml`：项目本地 Conda 环境的跨平台依赖定义。
- `requirements.txt`：不使用 Conda 时的 pip 依赖清单。
- `xm_encryptor.wasm`：XM 解密所需的 WebAssembly 模块。

## 说明

本工具参考了 [@aynakeya 的喜马拉雅 XM 文件解密分析](https://www.aynakeya.com/2023/03/15/ctf/xi-ma-la-ya-xm-wen-jian-jie-mi-ni-xiang-fen-xi/)。请仅处理自己合法获取并有权使用的音频文件。
