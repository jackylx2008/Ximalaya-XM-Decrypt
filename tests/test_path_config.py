"""跨平台默认路径配置测试。"""

from __future__ import annotations

import unittest

from path_config import resolve_default_paths


class DefaultPathsTest(unittest.TestCase):
    def test_macos_defaults(self) -> None:
        paths = resolve_default_paths({}, "Darwin", "/Users/sample")
        self.assertEqual(
            paths.input_path,
            "/Users/sample/SynologyDrive/有声书/ximalaya-xm",
        )
        self.assertEqual(paths.output_path, "/Users/sample/Desktop")

    def test_windows_defaults(self) -> None:
        paths = resolve_default_paths({}, "Windows", "C:/Users/sample")
        self.assertEqual(
            paths.input_path,
            r"D:\CloudStation\有声书\ximalaya-xm",
        )
        self.assertEqual(
            paths.output_path,
            r"C:\Users\sample\OneDrive\Desktop",
        )

    def test_explicit_paths_take_priority(self) -> None:
        paths = resolve_default_paths(
            {
                "INPUT_PATH": "~/audio/input",
                "OUTPUT_PATH": "~/audio/output",
                "CLOUDSTATION_ROOT": "~/ignored",
            },
            "Darwin",
            "/Users/sample",
        )
        self.assertEqual(paths.input_path, "/Users/sample/audio/input")
        self.assertEqual(paths.output_path, "/Users/sample/audio/output")

    def test_platform_cloudstation_override(self) -> None:
        paths = resolve_default_paths(
            {"CLOUDSTATION_ROOT_MACOS": "~/SynologyCustom"},
            "Darwin",
            "/Users/sample",
        )
        self.assertEqual(
            paths.input_path,
            "/Users/sample/SynologyCustom/有声书/ximalaya-xm",
        )


if __name__ == "__main__":
    unittest.main()
