"""POSIX integration tests for batch output capture without the fpnt binary."""

import builtins
import csv
import importlib
import json
import os
import select
import subprocess
import sys
import tempfile
import time
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
from types import ModuleType, SimpleNamespace
from unittest.mock import patch


@unittest.skipUnless(os.name == "posix", "requires POSIX nonblocking pipes")
class BatchOutputTest(unittest.TestCase):
    def setUp(self):
        # Import the actual runner without its optional plotting/memory packages.
        modules = {name: ModuleType(name) for name in ("psutil", "matplotlib", "matplotlib.pyplot")}
        with patch.dict(sys.modules, modules):
            self.runner = importlib.import_module("run_batch_fpnt")
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        previous_dir = Path.cwd()
        os.chdir(self.root)
        self.addCleanup(os.chdir, previous_dir)
        Path("config_fixture").mkdir()
        self.config = {"output_path": "fixture-output", "other_option": "preserved"}
        self.source_config = Path("config_fixture.json")
        self.source_config.write_text(json.dumps(self.config), encoding="utf-8")
        self.original_config = self.source_config.read_bytes()
        self.processes = []
        self.trial_configs = []
        self.events = []
        self.addCleanup(self.close_processes)

    def close_processes(self):
        for process in self.processes:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=10)
            process.stdout.close()

    @staticmethod
    def wait_for_file(path):
        deadline = time.monotonic() + 10
        while not Path(path).exists():
            if time.monotonic() > deadline:
                raise TimeoutError(f"child did not reach {path}")
            time.sleep(0.001)

    @staticmethod
    def dump_path(mc=1):
        return Path(f"batch_fpnt_dump_fixture_{mc}.txt")

    def run_child(self, body, after_launch=None, sample=None, concurrency=(1,)):
        executable = Path("fixture_child.py")
        executable.write_text(
            f"#!{sys.executable}\n"
            "import sys, time\n"
            "from pathlib import Path\n"
            "def write(data):\n"
            "    sys.stdout.buffer.write(data)\n"
            "    sys.stdout.buffer.flush()\n"
            "def await_gate(name):\n"
            "    deadline = time.monotonic() + 10\n"
            "    while not Path(name).exists():\n"
            "        if time.monotonic() > deadline:\n"
            "            raise TimeoutError(name)\n"
            "        time.sleep(0.001)\n"
            + body,
            encoding="utf-8",
        )
        executable.chmod(0o755)
        real_popen = subprocess.Popen

        def launch(args, **kwargs):
            self.trial_configs.append(json.loads(Path("config.json").read_text(encoding="utf-8")))
            process = real_popen(args, **kwargs)
            self.processes.append(process)
            if after_launch is None:
                # For small bursts, force exit-before-poll with the output
                # still in the real kernel pipe.
                process.wait(timeout=10)
            else:
                after_launch()
            return process

        def current_concurrency():
            return self.trial_configs[-1]["max_concurrency"]

        def observe_open(path, mode, *args, **kwargs):
            if Path(path).name == "batch_fpnt_result.txt" and mode == "a":
                mc = current_concurrency()
                self.events.append(("summary", mc, self.dump_path(mc).read_text(encoding="utf-8")))
            return builtins.open(path, mode, *args, **kwargs)

        def observe_plot(log_path):
            mc = current_concurrency()
            self.events.append(("plot", mc, self.dump_path(mc).read_text(encoding="utf-8")))
            self.assertEqual(Path(log_path).name, f"memory_footprint_fixture_{mc}.txt")

        def sample_memory(pid):
            self.assertEqual(pid, self.processes[-1].pid)
            return sample(self.processes[-1]) if sample else 1.25

        def short_sleep(seconds):
            if seconds == self.runner.SAMPLING_INTERVAL:
                time.sleep(0.001)

        with patch.multiple(
            self.runner,
            CHECK_RELEASE_MODE=False,
            concurrency_levels=concurrency,
            executable=f"./{executable}",
            get_tree_memory=sample_memory,
            call_external_plot=observe_plot,
            time=SimpleNamespace(time=time.time, sleep=short_sleep),
        ), patch.object(self.runner, "open", observe_open, create=True), patch.object(
            self.runner.subprocess, "Popen", launch
        ), redirect_stdout(StringIO()) as console:
            self.runner.run_batch()
        self.assertNotIn("[Failed]", console.getvalue())
        return console.getvalue()

    def summary(self):
        with Path("batch_fpnt_result.txt").open(newline="", encoding="utf-8") as handle:
            return list(csv.DictReader(handle))

    def assert_trial(self, expected, returncode=0):
        self.assertEqual(self.processes[0].returncode, returncode)
        summary = self.summary()
        self.assertEqual([row["return_code"] for row in summary], [str(returncode)])
        self.assertGreaterEqual(float(summary[0]["duration_sec"]), 0)
        self.assertEqual(self.dump_path().read_text(encoding="utf-8"), expected)
        self.assertEqual(self.events, [("summary", 1, expected), ("plot", 1, expected)])

    def test_child_exits_immediately_after_one_line(self):
        self.run_child("write(b'complete\\n')\n")
        self.assert_trial("complete\n")

    def test_multiple_pending_lines_preserve_utf8_and_order(self):
        output = "first\nsecond\n마지막\n"
        self.run_child(f"write({output.encode('utf-8')!r})\n")
        self.assert_trial(output)

    def test_final_fragment_without_newline(self):
        self.run_child("write(b'final fragment')\n")
        self.assert_trial("final fragment")

    def test_preserves_merged_stderr_and_nonzero_exit_status(self):
        self.run_child(
            "write(b'progress\\n')\n"
            "sys.stderr.write('failed\\n')\n"
            "sys.stderr.flush()\n"
            "sys.exit(7)\n"
        )
        self.assert_trial("progress\nfailed\n", returncode=7)

    def test_no_output(self):
        self.run_child("pass\n")
        self.assert_trial("")

    def test_releases_the_reaped_child_stdout(self):
        self.run_child("pass\n")
        self.assertEqual(self.processes[0].returncode, 0)
        self.assertTrue(self.processes[0].stdout.closed)

    def test_streamed_lines_and_buffered_tail_are_written_once(self):
        calls = []

        def sample(process):
            calls.append(process.pid)
            if len(calls) == 1:
                Path("allow_second").touch()
                self.wait_for_file("second_ready")
                return 2.25
            Path("allow_exit").touch()
            process.wait(timeout=10)
            return 4.5

        self.run_child(
            "write(b'streamed first\\n')\n"
            "Path('first_ready').touch()\n"
            "await_gate('allow_second')\n"
            "write(b'streamed second\\nbuffered tail\\n')\n"
            "Path('second_ready').touch()\n"
            "await_gate('allow_exit')\n"
            "write(b'final fragment')\n",
            after_launch=lambda: self.wait_for_file("first_ready"),
            sample=sample,
        )
        self.assertEqual(calls, [self.processes[0].pid] * 2)
        with Path("memory_footprint_fixture_1.txt").open(newline="", encoding="utf-8") as handle:
            samples = list(csv.DictReader(handle))
        self.assertEqual([float(row["total_rss_mb"]) for row in samples], [2.25, 4.5])
        elapsed = [float(row["elapsed_sec"]) for row in samples]
        self.assertEqual(elapsed, sorted(elapsed))
        self.assertTrue(all(value >= 0 for value in elapsed))
        self.assertEqual(float(self.summary()[0]["max_memory_mb"]), 4.5)
        self.assert_trial("streamed first\nstreamed second\nbuffered tail\nfinal fragment")

    def test_burst_larger_than_pipe_capacity_is_preserved(self):
        line = b"x" * 4095 + b"\n"
        prefix = line * 64

        def sample(process):
            # Let the polling loop empty the kernel pipe before joining the
            # child. Otherwise even the small final write could block.
            if Path("tail_ready").exists() and not select.select([process.stdout], [], [], 0)[0]:
                Path("allow_tail").touch()
                process.wait(timeout=10)
            return 2.0

        self.run_child(
            "write((b'x' * 4095 + b'\\n') * 64)\n"
            "Path('tail_ready').touch()\n"
            "await_gate('allow_tail')\n"
            "write(b'complete')\n",
            after_launch=lambda: None,
            sample=sample,
        )
        self.assert_trial(prefix.decode("ascii") + "complete")

    def test_configuration_and_concurrency_iteration_are_preserved(self):
        Path("config_missing").mkdir()
        console = self.run_child("pass\n", concurrency=(2, 1))
        self.assertIn("config_missing.json not found", console)
        self.assertEqual(self.source_config.read_bytes(), self.original_config)
        self.assertEqual(self.trial_configs, [
            dict(self.config, max_concurrency=2, multiprocessing=True, output_path="fixture-output_2"),
            dict(self.config, max_concurrency=1, multiprocessing=False, output_path="fixture-output_1"),
        ])
        self.assertEqual([(row["exp_name"], row["max_concurrency"], row["return_code"]) for row in self.summary()],
                         [("fixture", "2", "0"), ("fixture", "1", "0")])
        self.assertEqual(self.events, [("summary", 2, ""), ("plot", 2, ""), ("summary", 1, ""), ("plot", 1, "")])
