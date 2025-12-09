<h1 align="center">喜马拉雅xm文件解密工具</h1>
<h4 align="center"># 喜马拉雅 XM 文件解密工具

这是一个用于批量解密喜马拉雅 `.xm` 音频文件的命令行工具。

## 功能特点

* **批量处理**：支持选择输入目录，自动遍历并解密所有子目录中的 `.xm` 文件。
* **保持目录结构**：解密后的文件会按照原有的目录结构保存到输出目录。
* **日志记录**：详细记录操作日志，方便排查问题（日志文件默认每次运行会重置）。

## 环境要求

* Python 3.x

## 使用方法

1. **运行程序**：
   在终端中运行以下命令启动工具：

   ```bash
   python main.py
   ```

2. **操作流程**：
   * 程序启动后，请根据提示输入包含 `.xm` 文件的**输入目录**路径。
   * 然后输入解密后文件保存的**输出目录**路径。
   * 程序将自动开始处理，并在终端显示进度。

## 注意事项

* 目前的解密逻辑仅为演示/占位符（简单的异或操作），实际使用时需要根据具体的加密算法修改 `main.py` 中的 `decrypt_xm_file` 函数。
* 日志文件保存在 `logs/` 目录下，文件名为 `app.log`。

## 开发说明

* `main.py`: 主程序入口，包含业务逻辑。
* `logging_config.py`: 日志配置文件。</h4>

### 说明

由于喜马拉雅官方客户端下载的音频文件为加密格式，无法在普通播放器中播放，所以我写了这个小工具来解密喜马拉雅下载的音频文件。本工具参考@aynakeya的[博文](https://www.aynakeya.com/2023/03/15/ctf/xi-ma-la-ya-xm-wen-jian-jie-mi-ni-xiang-fen-xi/)，并加入了批量解密的功能。我还写了一个程序[Ximalaya-Downloader](https://github.com/Diaoxiaozhang/Ximalaya-Downloader)，用于直接爬取未加密的喜马拉雅音频文件。本工具作为Ximalaya-Downloader的补充，当每日下载vip音频达到上限时，可以使用客户端下载加密的xm文件并使用本工具解密。

在使用该软件时，请确保xm_encryptor.wasm文件与主程序文件处在同一目录下，最好是一个单独的文件夹。

正确安装[`Wasmer`](https://docs.wasmer.io/install)，Python 对应的版本为3.7.9，高版本的Python运行会提示"ImportError: Wasmer is not available on this system"

在`Anaconda Prompt` 能正常切换环境

```bash
conda create -n py37 python=3.7.9
conda activate py37
pip install mutagen pycryptodome wasmer python-magic-bin wasmer_compiler_cranelift
```
