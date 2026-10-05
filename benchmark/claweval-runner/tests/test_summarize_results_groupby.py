# Copyright 2026 Alibaba Cloud
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Tests for ``summarize_results.py --group-by difficulty`` (subprocess-driven)."""

from __future__ import annotations

import csv
import io
import json
import subprocess
import sys
from pathlib import Path

SCRIPT_PATH = Path(__file__).resolve().parents[1] / "scripts" / "summarize_results.py"


def _trial(score=None, passed=False, wall=None, error=None, **extra):
    trial: dict = {"trial": 1, "passed": passed}
    if score is not None:
        trial["task_score"] = score
    if wall is not None:
        trial["wall_time_s"] = wall
    if error is not None:
        trial["error"] = error
    trial.update(extra)
    return trial


def _task(task_id, difficulty, trials, name=""):
    task: dict = {"task_id": task_id, "task_name": name, "trials": trials}
    if difficulty is not _MISSING:
        task["difficulty"] = difficulty
    return task


class _Missing:
    pass


_MISSING = _Missing()


def _write_input(tmp_path: Path, data) -> Path:
    path = tmp_path / "batch_results.json"
    path.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
    return path


def _run(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(SCRIPT_PATH), *args],
        capture_output=True,
        text=True,
        encoding="utf-8",
    )


def _run_csv(path: Path, *extra: str) -> list[dict[str, str]]:
    proc = _run("--input", str(path), "--format", "csv", *extra)
    assert proc.returncode == 0, proc.stderr
    return list(csv.DictReader(io.StringIO(proc.stdout)))


GROUPED_HEADER = [
    "Group",
    "Tasks",
    "Trials",
    "Errors",
    "Measured Trials",
    "Passed",
    "Pass Rate",
    "Mean Score",
    "Mean Wall Time(s)",
]


def _fixture_default():
    return [
        _task("A", "easy", [
            _trial(score=0.9, passed=True, wall=100.0),
            _trial(score=0.4, passed=False, wall=200.0),
            _trial(score=0.0, passed=False, wall=5.0, error="agent failed: boom"),
        ]),
        _task("B", "easy", [
            _trial(score=0.95, passed=True, wall=50.0),
        ]),
        _task("C", "medium", [
            _trial(score=0.0, passed=False, wall=1.0, error="fixture missing: x"),
            _trial(score=0.0, passed=False, wall=1.0, error="agent failed: y"),
        ]),
        _task("D", "", [
            _trial(score=0.5, passed=False, wall=10.0),
        ]),
        _task("E", None, [
            _trial(score=0.8, passed=True, wall=20.0),
        ]),
        _task("F", "自定义,难度", [
            _trial(score=0.7, passed=True, wall=30.0),
        ]),
    ]


def test_group_by_difficulty_table_counts_and_weighted_rates(tmp_path):
    path = _write_input(tmp_path, _fixture_default())

    proc = _run("--input", str(path), "--group-by", "difficulty")

    assert proc.returncode == 0, proc.stderr
    rows = _run_csv(path, "--group-by", "difficulty")
    assert list(rows[0].keys()) == GROUPED_HEADER
    by_group = {row["Group"]: row for row in rows}
    assert [row["Group"] for row in rows] == ["easy", "medium", "自定义,难度", "unknown"]

    easy = by_group["easy"]
    assert easy["Tasks"] == "2"
    assert easy["Trials"] == "4"
    assert easy["Errors"] == "1"
    assert easy["Measured Trials"] == "3"
    assert easy["Passed"] == "2"
    assert easy["Pass Rate"] == "2/3 (66.7%)"
    assert easy["Mean Score"] == "0.75 (n=3)"
    assert easy["Mean Wall Time(s)"] == "116.67 (n=3)"

    medium = by_group["medium"]
    assert medium["Tasks"] == "1"
    assert medium["Trials"] == "2"
    assert medium["Errors"] == "2"
    assert medium["Measured Trials"] == "0"
    assert medium["Passed"] == "0"
    assert medium["Pass Rate"] == ""
    assert medium["Mean Score"] == ""
    assert medium["Mean Wall Time(s)"] == ""

    unknown = by_group["unknown"]
    assert unknown["Tasks"] == "2"
    assert unknown["Trials"] == "2"
    assert unknown["Errors"] == "0"
    assert unknown["Pass Rate"] == "1/2 (50.0%)"

    unicode_group = by_group["自定义,难度"]
    assert unicode_group["Pass Rate"] == "1/1 (100.0%)"
    assert unicode_group["Mean Score"] == "0.7 (n=1)"

    # Table output must render the same grouped rows and the summary line.
    table = _run("--input", str(path), "--group-by", "difficulty")
    assert table.returncode == 0, table.stderr
    assert "Pass Rate" in table.stdout
    assert "66.7%" in table.stdout
    assert "Summary:" in table.stdout


def test_group_by_difficulty_excludes_errored_measurements(tmp_path):
    # The errored trial carries a high score and huge wall time; it must not
    # leak into means or rates.
    data = [
        _task("A", "easy", [
            _trial(score=0.5, passed=False, wall=10.0),
            _trial(score=0.9, passed=True, wall=999999.0, error="boom"),
        ]),
    ]
    path = _write_input(tmp_path, data)

    rows = _run_csv(path, "--group-by", "difficulty")

    assert len(rows) == 1
    row = rows[0]
    assert row["Errors"] == "1"
    assert row["Measured Trials"] == "1"
    assert row["Mean Score"] == "0.5 (n=1)"
    assert row["Mean Wall Time(s)"] == "10.00 (n=1)"
    assert row["Pass Rate"] == "0/1 (0.0%)"


def test_group_by_difficulty_weights_by_trials_not_task_means(tmp_path):
    # 3/4 trials passed overall; averaging per-task means would give 50%.
    data = [
        _task("X", "hard", [
            _trial(score=1.0, passed=True, wall=1.0),
            _trial(score=1.0, passed=True, wall=1.0),
            _trial(score=1.0, passed=True, wall=1.0),
        ]),
        _task("Y", "hard", [
            _trial(score=0.0, passed=False, wall=1.0),
        ]),
    ]
    path = _write_input(tmp_path, data)

    rows = _run_csv(path, "--group-by", "difficulty")

    assert rows[0]["Pass Rate"] == "3/4 (75.0%)"
    assert rows[0]["Mean Score"] == "0.75 (n=4)"


def test_group_by_difficulty_missing_or_invalid_numeric_fields(tmp_path):
    data = [
        _task("A", "easy", [
            _trial(passed=True, wall=None, task_score=None),
            _trial(score="broken", passed=False, wall=8.0),
            _trial(passed=False, wall=4.0),  # score key missing entirely
        ]),
    ]
    path = _write_input(tmp_path, data)

    rows = _run_csv(path, "--group-by", "difficulty")

    row = rows[0]
    assert row["Measured Trials"] == "3"
    assert row["Pass Rate"] == "1/3 (33.3%)"
    assert row["Mean Score"] == ""  # no numeric score at all
    assert row["Mean Wall Time(s)"] == "6.00 (n=2)"


def test_group_by_difficulty_large_finite_durations(tmp_path):
    data = [
        _task("A", "easy", [
            _trial(score=0.5, passed=True, wall=1e9),
            _trial(score=0.5, passed=True, wall=3e9),
        ]),
    ]
    path = _write_input(tmp_path, data)

    rows = _run_csv(path, "--group-by", "difficulty")

    assert rows[0]["Mean Wall Time(s)"] == "2000000000.00 (n=2)"
    assert "inf" not in rows[0]["Mean Wall Time(s)"]
    assert "e+" not in rows[0]["Mean Wall Time(s)"]


def test_group_by_difficulty_invalid_shape_fails_before_replacing_output(tmp_path):
    path = _write_input(tmp_path, {"not": "a list"})
    out = tmp_path / "results.csv"
    out.write_text("sentinel", encoding="utf-8")

    proc = _run("--input", str(path), "--group-by", "difficulty", "--format", "csv", "-o", str(out))

    assert proc.returncode != 0
    assert "batch_results.json" in proc.stderr or "Error" in proc.stderr
    assert out.read_text(encoding="utf-8") == "sentinel"

    bad_dir = tmp_path / "bad"
    bad_dir.mkdir()
    bad_trials = _write_input(bad_dir, [{"task_id": "A", "difficulty": "easy", "trials": "nope"}])
    proc2 = _run("--input", str(bad_trials), "--group-by", "difficulty", "--format", "csv", "-o", str(out))
    assert proc2.returncode != 0
    assert out.read_text(encoding="utf-8") == "sentinel"


def test_group_by_difficulty_empty_difficulty_labels_group_under_unknown(tmp_path):
    data = [
        _task("A", "", [_trial(score=1.0, passed=True, wall=1.0)]),
        _task("B", None, [_trial(score=0.0, passed=False, wall=1.0)]),
        _task("C", "   ", [_trial(score=0.0, passed=False, wall=1.0)]),
        _task("D", _MISSING, [_trial(score=0.0, passed=False, wall=1.0)]),
    ]
    path = _write_input(tmp_path, data)

    rows = _run_csv(path, "--group-by", "difficulty")

    assert [row["Group"] for row in rows] == ["unknown"]
    assert rows[0]["Tasks"] == "4"
    assert rows[0]["Trials"] == "4"
    assert rows[0]["Pass Rate"] == "1/4 (25.0%)"


def test_default_task_view_rows_unchanged(tmp_path):
    data = _fixture_default()
    path = _write_input(tmp_path, data)

    proc = _run("--input", str(path), "--format", "csv")
    assert proc.returncode == 0, proc.stderr
    rows = list(csv.reader(io.StringIO(proc.stdout)))
    header = rows[0]
    assert header[:3] == ["Task ID", "Task Name", "Difficulty"]
    assert "Trial" in header and "Pass Rate" not in header
    # First data row belongs to task A with its three trial sub-rows.
    assert rows[1][0] == "A"
    assert rows[1][2] == "easy"
    assert rows[1][3] == "#1"
    assert rows[2][0] == "" and rows[2][3] == "#2"
    assert rows[3][0] == "" and rows[3][3] == "#3"
    # The errored trial row keeps its trial-level values.
    assert rows[3][15] == "0"
    assert rows[3][16] == "N"

    table = _run("--input", str(path))
    assert table.returncode == 0, table.stderr
    assert "Summary: 6 tasks" in table.stdout


def test_group_by_difficulty_rejects_unknown_group_key(tmp_path):
    path = _write_input(tmp_path, [])
    proc = _run("--input", str(path), "--group-by", "task")
    assert proc.returncode != 0
