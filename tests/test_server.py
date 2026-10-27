"""Unit tests for frame-mcp argument building. No network, no subprocess."""

import json
import os
import unittest

from frame_mcp import server


class ScanArgsTest(unittest.TestCase):
    def test_minimal_defaults(self):
        args = server._build_scan_args("/code")
        self.assertEqual(
            args, ["scan", "/code", "-f", "json", "--fail-on", "none"]
        )

    def test_all_options(self):
        args = server._build_scan_args(
            "/code",
            language="python",
            ai=True,
            changed_ref="HEAD~1",
            files=["a.py", "b.py"],
            baseline="base.json",
            min_severity="high",
            fail_on="critical",
            root="/root",
            no_cross_file=True,
            packs=["p1.toml", "p2.toml"],
        )
        self.assertEqual(
            args,
            [
                "scan", "/code", "-f", "json", "--fail-on", "critical",
                "-l", "python",
                "--ai",
                "--changed", "HEAD~1",
                "--files", "a.py", "b.py",
                "--baseline", "base.json",
                "--min-severity", "high",
                "--root", "/root",
                "--no-cross-file",
                "--pack", "p1.toml",
                "--pack", "p2.toml",
            ],
        )

    def test_changed_ref_empty_string_included(self):
        # An empty ref is meaningful (frame treats --changed with no value as HEAD).
        args = server._build_scan_args("/code", changed_ref="")
        self.assertIn("--changed", args)
        self.assertEqual(args[args.index("--changed") + 1], "")


class WriteBaselineArgsTest(unittest.TestCase):
    def test_args(self):
        self.assertEqual(
            server._build_write_baseline_args("/code", "b.json"),
            ["scan", "/code", "--write-baseline", "b.json", "--fail-on", "none"],
        )


class VerifyArgsTest(unittest.TestCase):
    def test_no_ids(self):
        self.assertEqual(
            server._build_verify_args("f.json"),
            ["verify", "f.json", "-f", "json"],
        )

    def test_with_ids(self):
        self.assertEqual(
            server._build_verify_args("-", ids=["aa", "bb"]),
            ["verify", "-", "-f", "json", "--id", "aa", "--id", "bb"],
        )


class FixArgsTest(unittest.TestCase):
    def test_default_diff(self):
        args = server._build_fix_args("/code", "g.json")
        self.assertEqual(
            args, ["fix", "/code", "--guidance", "g.json", "--format", "json"]
        )
        self.assertNotIn("--in-place", args)

    def test_in_place(self):
        args = server._build_fix_args("/code", "g.json", in_place=True)
        self.assertIn("--in-place", args)


class ExploitArgsTest(unittest.TestCase):
    def test_minimal(self):
        self.assertEqual(
            server._build_exploit_args("http://app:8080"),
            ["exploit", "--target", "http://app:8080", "--format", "json"],
        )

    def test_full(self):
        args = server._build_exploit_args(
            "http://app:8080",
            guidance_file="g.json",
            goal="read a secret",
            success_check="test -f /tmp/pwned",
            max_steps=10,
        )
        self.assertEqual(
            args,
            [
                "exploit", "--target", "http://app:8080", "--format", "json",
                "--guidance", "g.json",
                "--goal", "read a secret",
                "--success-check", "test -f /tmp/pwned",
                "--max-steps", "10",
            ],
        )


class SolveArgsTest(unittest.TestCase):
    def test_no_model(self):
        self.assertEqual(
            server._build_solve_args("x |-> 5 |- x |-> 5"),
            ["solve", "x |-> 5 |- x |-> 5", "--format", "json"],
        )

    def test_with_model(self):
        self.assertEqual(
            server._build_solve_args("emp |- x |-> 5", model=True),
            ["solve", "emp |- x |-> 5", "--format", "json", "--model"],
        )


class PacksArgsTest(unittest.TestCase):
    def test_list_no_path(self):
        self.assertEqual(server._build_packs_list_args(), ["packs", "list"])

    def test_list_with_path(self):
        self.assertEqual(
            server._build_packs_list_args("/proj"),
            ["packs", "list", "--project", "/proj"],
        )

    def test_check(self):
        self.assertEqual(
            server._build_packs_check_args(["a.toml", "b.toml"]),
            ["packs", "check", "a.toml", "b.toml"],
        )


class FindingsTempfileTest(unittest.TestCase):
    def test_dict_written_as_json(self):
        path = server._write_findings_tempfile({"schema_version": 1, "files": []})
        try:
            with open(path, encoding="utf-8") as fh:
                data = json.load(fh)
            self.assertEqual(data["schema_version"], 1)
        finally:
            os.unlink(path)

    def test_string_passthrough(self):
        raw = '{"a": 1}'
        path = server._write_findings_tempfile(raw)
        try:
            with open(path, encoding="utf-8") as fh:
                self.assertEqual(fh.read(), raw)
        finally:
            os.unlink(path)


class ParseOutputTest(unittest.TestCase):
    class _Proc:
        def __init__(self, stdout, stderr="", returncode=0):
            self.stdout = stdout
            self.stderr = stderr
            self.returncode = returncode

    def test_json_parsed(self):
        out = server._parse_output(self._Proc('{"ok": true}'))
        self.assertEqual(out, {"ok": True})

    def test_non_json_fallback(self):
        out = server._parse_output(self._Proc("not json", stderr="boom", returncode=1))
        self.assertEqual(out["stdout"], "not json")
        self.assertEqual(out["stderr"], "boom")
        self.assertEqual(out["exit_code"], 1)


class FrameExecutableTest(unittest.TestCase):
    def test_returns_string(self):
        self.assertIsInstance(server._frame_executable(), str)


if __name__ == "__main__":
    unittest.main()
