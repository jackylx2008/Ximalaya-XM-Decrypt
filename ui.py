"""喜马拉雅 XM 解密工具桌面界面。"""

from __future__ import annotations

import logging
import queue
import threading
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, scrolledtext, ttk
from typing import Any, Callable


class QueueLogHandler(logging.Handler):
    """将日志消息传递给 Tk 主线程。"""

    def __init__(self, event_queue: queue.Queue[tuple[Any, ...]]) -> None:
        super().__init__()
        self.event_queue = event_queue

    def emit(self, record: logging.LogRecord) -> None:
        self.event_queue.put(("log", self.format(record)))


class DecryptApp:
    def __init__(
        self,
        root: tk.Tk,
        process_batch: Callable[..., Any],
        default_input: str,
        default_output: str,
        default_keyword: str,
    ) -> None:
        self.root = root
        self.process_batch = process_batch
        self.events: queue.Queue[tuple[Any, ...]] = queue.Queue()
        self.worker: threading.Thread | None = None
        self.log_handler: QueueLogHandler | None = None

        self.input_var = tk.StringVar(value=default_input)
        self.output_var = tk.StringVar(value=default_output)
        self.keyword_var = tk.StringVar(value=default_keyword)
        self.keyword_filter_var = tk.BooleanVar(value=bool(default_keyword.strip()))
        self.status_var = tk.StringVar(value="文件总数：0  |  进度：0/0（0.0%）  |  当前文件：等待开始")
        self.progress_var = tk.DoubleVar(value=0)

        self._configure_window()
        self._build_ui()
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)
        self.root.after(100, self._poll_events)

    def _configure_window(self) -> None:
        self.root.title("喜马拉雅 XM 文件解密工具")
        self.root.geometry("860x640")
        self.root.minsize(720, 520)

        style = ttk.Style(self.root)
        if "vista" in style.theme_names():
            style.theme_use("vista")
        style.configure("Title.TLabel", font=("Microsoft YaHei UI", 17, "bold"))
        style.configure("Hint.TLabel", foreground="#666666")

    def _build_ui(self) -> None:
        container = ttk.Frame(self.root, padding=20)
        container.grid(row=0, column=0, sticky="nsew")
        self.root.rowconfigure(0, weight=1)
        self.root.columnconfigure(0, weight=1)
        container.columnconfigure(1, weight=1)
        container.rowconfigure(7, weight=1)

        ttk.Label(container, text="喜马拉雅 XM 文件解密", style="Title.TLabel").grid(
            row=0, column=0, columnspan=3, sticky="w", pady=(0, 5)
        )
        ttk.Label(
            container,
            text="目录可直接输入或粘贴，也可通过右侧“浏览…”按钮在资源管理器中选择。",
            style="Hint.TLabel",
        ).grid(row=1, column=0, columnspan=3, sticky="w", pady=(0, 18))

        self._add_directory_row(container, 2, "输入目录", self.input_var, self._browse_input)
        self._add_directory_row(container, 3, "输出目录", self.output_var, self._browse_output)

        ttk.Checkbutton(
            container,
            text="按文件夹关键词筛选",
            variable=self.keyword_filter_var,
            command=self._toggle_keyword_filter,
        ).grid(row=4, column=0, sticky="w", padx=(0, 12), pady=7)
        self.keyword_entry = ttk.Entry(container, textvariable=self.keyword_var)
        self.keyword_entry.grid(row=4, column=1, columnspan=2, sticky="ew", pady=7)
        self._toggle_keyword_filter()

        actions = ttk.Frame(container)
        actions.grid(row=5, column=0, columnspan=3, sticky="ew", pady=(16, 10))
        actions.columnconfigure(0, weight=1)
        self.start_button = ttk.Button(
            actions, text="开始解码", command=self._start_processing
        )
        self.start_button.grid(row=0, column=1)

        self.progress = ttk.Progressbar(
            container, variable=self.progress_var, maximum=100, mode="determinate"
        )
        self.progress.grid(row=6, column=0, columnspan=3, sticky="ew", pady=(0, 6))

        log_frame = ttk.LabelFrame(container, text="处理日志", padding=8)
        log_frame.grid(row=7, column=0, columnspan=3, sticky="nsew", pady=(0, 10))
        log_frame.rowconfigure(0, weight=1)
        log_frame.columnconfigure(0, weight=1)
        self.log_text = scrolledtext.ScrolledText(
            log_frame,
            height=15,
            state="disabled",
            wrap="word",
            font=("Consolas", 9),
        )
        self.log_text.grid(row=0, column=0, sticky="nsew")

        status_bar = ttk.Frame(container, relief="sunken", borderwidth=1, padding=(8, 5))
        status_bar.grid(row=8, column=0, columnspan=3, sticky="ew")
        ttk.Label(status_bar, textvariable=self.status_var, anchor="w").pack(
            fill="x", expand=True
        )

    def _add_directory_row(
        self,
        parent: ttk.Frame,
        row: int,
        label: str,
        variable: tk.StringVar,
        browse_command: Callable[[], None],
    ) -> None:
        ttk.Label(parent, text=label).grid(
            row=row, column=0, sticky="w", padx=(0, 12), pady=7
        )
        ttk.Entry(parent, textvariable=variable).grid(
            row=row, column=1, sticky="ew", pady=7
        )
        ttk.Button(parent, text="浏览…", command=browse_command).grid(
            row=row, column=2, padx=(10, 0), pady=7
        )

    def _browse_input(self) -> None:
        selected = filedialog.askdirectory(
            parent=self.root,
            title="选择包含专辑文件夹的输入目录",
            initialdir=self._initial_directory(self.input_var.get()),
            mustexist=True,
        )
        if selected:
            self.input_var.set(selected)

    def _browse_output(self) -> None:
        selected = filedialog.askdirectory(
            parent=self.root,
            title="选择解密文件输出目录",
            initialdir=self._initial_directory(self.output_var.get()),
            mustexist=False,
        )
        if selected:
            self.output_var.set(selected)

    def _toggle_keyword_filter(self) -> None:
        state = "normal" if self.keyword_filter_var.get() else "disabled"
        self.keyword_entry.configure(state=state)

    @staticmethod
    def _initial_directory(value: str) -> str:
        path = Path(value.strip().strip('"')).expanduser() if value.strip() else Path.cwd()
        if path.is_dir():
            return str(path)
        if path.parent.is_dir():
            return str(path.parent)
        return str(Path.cwd())

    def _start_processing(self) -> None:
        if self.worker and self.worker.is_alive():
            return

        input_path = self.input_var.get().strip().strip('"')
        output_path = self.output_var.get().strip().strip('"')
        keyword = self.keyword_var.get().strip()
        if not input_path or not Path(input_path).expanduser().is_dir():
            messagebox.showerror("输入错误", "请选择一个存在的输入目录。", parent=self.root)
            return
        if not output_path:
            messagebox.showerror("输入错误", "请选择或填写输出目录。", parent=self.root)
            return
        if self.keyword_filter_var.get() and not keyword:
            messagebox.showerror("输入错误", "请填写文件夹名称关键字。", parent=self.root)
            return
        effective_keyword = keyword if self.keyword_filter_var.get() else ""

        self.input_var.set(input_path)
        self.output_var.set(output_path)
        self.progress_var.set(0)
        self.status_var.set("文件总数：扫描中  |  进度：0/0（0.0%）  |  当前文件：正在扫描目录…")
        self._clear_log()
        self.start_button.configure(state="disabled")

        self.log_handler = QueueLogHandler(self.events)
        self.log_handler.setFormatter(
            logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
        )
        logging.getLogger().addHandler(self.log_handler)

        self.worker = threading.Thread(
            target=self._run_processing,
            args=(input_path, output_path, effective_keyword),
            daemon=True,
            name="xm-decrypt-worker",
        )
        self.worker.start()

    def _run_processing(self, input_path: str, output_path: str, keyword: str) -> None:
        try:
            result = self.process_batch(
                input_path,
                output_path,
                keyword,
                progress_callback=self._report_progress,
            )
            self.events.put(("done", result))
        except Exception as exc:
            logging.getLogger(__name__).exception("批量解码失败")
            self.events.put(("error", str(exc)))
        finally:
            if self.log_handler is not None:
                logging.getLogger().removeHandler(self.log_handler)
                self.log_handler = None

    def _report_progress(
        self, current: int, total: int, file_path: Path, success: bool | None
    ) -> None:
        self.events.put(("progress", current, total, file_path.name, success))

    def _poll_events(self) -> None:
        try:
            while True:
                event = self.events.get_nowait()
                event_type = event[0]
                if event_type == "log":
                    self._append_log(event[1])
                elif event_type == "progress":
                    _, current, total, file_name, success = event
                    percent = current / total * 100 if total else 0
                    self.progress_var.set(percent)
                    if success is None:
                        current_text = f"{file_name}（处理中）"
                    else:
                        outcome = "成功" if success else "失败"
                        current_text = f"{file_name}（{outcome}）"
                    self.status_var.set(
                        f"文件总数：{total}  |  进度：{current}/{total}"
                        f"（{percent:.1f}%）  |  当前文件：{current_text}"
                    )
                elif event_type == "done":
                    self._finish_success(event[1])
                elif event_type == "error":
                    self._finish_error(event[1])
        except queue.Empty:
            pass
        if self.root.winfo_exists():
            self.root.after(100, self._poll_events)

    def _finish_success(self, result: Any) -> None:
        self.start_button.configure(state="normal")
        if result.total_files:
            self.progress_var.set(100)
        percent = 100.0 if result.total_files else 0.0
        self.status_var.set(
            f"文件总数：{result.total_files}  |  "
            f"进度：{result.total_files}/{result.total_files}（{percent:.1f}%）  |  "
            f"处理完成：成功 {result.succeeded}，失败 {result.failed}"
        )
        summary = (
            f"匹配目录 {result.matching_directories}，文件总数 {result.total_files}，"
            f"成功 {result.succeeded}，失败 {result.failed}"
        )
        messagebox.showinfo("处理完成", summary, parent=self.root)

    def _finish_error(self, message: str) -> None:
        self.start_button.configure(state="normal")
        self.status_var.set("处理失败，请查看日志信息。")
        messagebox.showerror("处理失败", message, parent=self.root)

    def _append_log(self, message: str) -> None:
        self.log_text.configure(state="normal")
        self.log_text.insert("end", message + "\n")
        self.log_text.see("end")
        self.log_text.configure(state="disabled")

    def _clear_log(self) -> None:
        self.log_text.configure(state="normal")
        self.log_text.delete("1.0", "end")
        self.log_text.configure(state="disabled")

    def _on_close(self) -> None:
        if self.worker and self.worker.is_alive():
            messagebox.showwarning(
                "任务正在运行",
                "解码任务尚未结束，请等待处理完成后再关闭窗口。",
                parent=self.root,
            )
            return
        self.root.destroy()


def launch_ui(
    process_batch: Callable[..., Any],
    default_input: str = "",
    default_output: str = "./output",
    default_keyword: str = "",
) -> None:
    root = tk.Tk()
    DecryptApp(root, process_batch, default_input, default_output, default_keyword)
    root.mainloop()
