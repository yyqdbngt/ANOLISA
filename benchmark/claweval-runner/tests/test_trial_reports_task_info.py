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

"""Tests for scripts/generate_trial_reports.py task.yaml loading.

Regression tests for malformed task.yaml prompt blocks: a null prompt, a
plain-string prompt, a null prompt.text, a null reference_solution, and an
empty task.yaml each used to raise (AttributeError/TypeError) inside
load_task_info and abort the whole report run after some reports were
already written.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest


SCRIPT_PATH = (
    Path(__file__).resolve().parents[1] / "scripts" / "generate_trial_reports.py"
)


@pytest.fixture(scope="module")
def script_mod():
    spec = importlib.util.spec_from_file_location(
        "test_trial_reports_script", SCRIPT_PATH
    )
    mod = importlib.util.module_from_spec(spec)
    sys.modules["test_trial_reports_script"] = mod
    spec.loader.exec_module(mod)  # type: ignore[union-attr]
    return mod


def write_task(tmp_path, body: str) -> str:
    tasks_dir = tmp_path / "tasks"
    task_dir = tasks_dir / "C01_task"
    task_dir.mkdir(parents=True, exist_ok=True)
    (task_dir / "task.yaml").write_text(body, encoding="utf-8")
    return str(tasks_dir)


def test_null_prompt_block_is_tolerated(script_mod, tmp_path):
    tasks_dir = write_task(tmp_path, "task_id: C01_task\ntask_name: t\nprompt:\n")
    info = script_mod.load_task_info("C01_task", tasks_dir)
    assert info["task_id"] == "C01_task"
    assert info["prompt"] == ""


def test_plain_string_prompt_is_tolerated(script_mod, tmp_path):
    tasks_dir = write_task(
        tmp_path, "task_id: C01_task\ntask_name: t\nprompt: just a plain string\n"
    )
    info = script_mod.load_task_info("C01_task", tasks_dir)
    assert info["prompt"] == ""


def test_null_prompt_text_is_tolerated(script_mod, tmp_path):
    tasks_dir = write_task(
        tmp_path, "task_id: C01_task\ntask_name: t\nprompt:\n  text:\n"
    )
    info = script_mod.load_task_info("C01_task", tasks_dir)
    assert info["prompt"] == ""


def test_null_reference_solution_is_tolerated(script_mod, tmp_path):
    tasks_dir = write_task(
        tmp_path,
        "task_id: C01_task\ntask_name: t\nprompt:\n  text: hi\nreference_solution:\n",
    )
    info = script_mod.load_task_info("C01_task", tasks_dir)
    assert info["reference_solution"] == ""


def test_empty_task_yaml_is_tolerated(script_mod, tmp_path):
    tasks_dir = write_task(tmp_path, "")
    info = script_mod.load_task_info("C01_task", tasks_dir)
    assert info["task_id"] == "C01_task"
    assert info["prompt"] == ""


def test_well_formed_task_yaml_still_reads_fields(script_mod, tmp_path):
    tasks_dir = write_task(
        tmp_path,
        "task_id: C01_task\ntask_name: mortgage\nprompt:\n  text: compute the repayment\n"
        "reference_solution: amortize first\nprimary_dimensions:\n  - correctness\n",
    )
    info = script_mod.load_task_info("C01_task", tasks_dir)
    assert info["prompt"] == "compute the repayment"
    assert info["reference_solution"] == "amortize first"
    assert info["primary_dimensions"] == ["correctness"]
