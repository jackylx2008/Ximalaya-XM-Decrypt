"""跨平台默认路径解析。

机器本地环境变量优先于平台默认值，业务与 UI 模块只接收解析后的路径，
不需要自行判断操作系统。
"""

from __future__ import annotations

import os
import platform
from dataclasses import dataclass
from pathlib import Path, PurePath, PurePosixPath, PureWindowsPath
from typing import Mapping


@dataclass(frozen=True)
class DefaultPaths:
    input_path: str
    output_path: str


def resolve_default_paths(
    environ: Mapping[str, str] | None = None,
    system_name: str | None = None,
    home: str | Path | None = None,
) -> DefaultPaths:
    """解析输入、输出默认目录，支持环境变量覆盖。"""
    values = os.environ if environ is None else environ
    system = system_name or platform.system()
    raw_home = Path.home() if home is None else home
    home_path = _path_for_system(str(raw_home), system)

    input_override = values.get("INPUT_PATH", "").strip()
    output_override = values.get("OUTPUT_PATH", "").strip()
    cloud_root = _resolve_cloudstation_root(values, system, home_path)

    if input_override:
        input_path = _expand_path(input_override, home_path, system)
    else:
        input_path = cloud_root / "有声书" / "ximalaya-xm"

    if output_override:
        output_path = _expand_path(output_override, home_path, system)
    elif system == "Windows":
        output_path = _path_for_system(home_path, system) / "OneDrive" / "Desktop"
    else:
        output_path = _path_for_system(home_path, system) / "Desktop"

    return DefaultPaths(str(input_path), str(output_path))


def _resolve_cloudstation_root(
    environ: Mapping[str, str], system: str, home: PurePath
):
    platform_variable = {
        "Windows": "CLOUDSTATION_ROOT_WINDOWS",
        "Darwin": "CLOUDSTATION_ROOT_MACOS",
        "Linux": "CLOUDSTATION_ROOT_LINUX",
    }.get(system)
    configured = environ.get("CLOUDSTATION_ROOT", "").strip()
    if not configured and platform_variable:
        configured = environ.get(platform_variable, "").strip()
    if configured:
        return _expand_path(configured, home, system)

    if system == "Windows":
        return PureWindowsPath("D:/CloudStation")
    if system == "Darwin":
        return home / "SynologyDrive"
    return home / "CloudStation"


def _expand_path(value: str, home: PurePath, system: str):
    if value == "~" or value.startswith("~/") or value.startswith("~\\"):
        value = str(home) + value[1:]
    return _path_for_system(value, system)


def _path_for_system(value: str | Path | PurePath, system: str) -> PurePath:
    if system == "Windows":
        return PureWindowsPath(str(value))
    return PurePosixPath(str(value).replace("\\", "/"))
