#!/usr/bin/env python3

from __future__ import annotations

import concurrent.futures
import json
import os
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from primitive_bench import (  # noqa: E402
    COMPLETION_TOOL_FORMATS,
    EmulatedEnv,
    Event,
    SynchronousBatchClient,
    Task,
    extract_xml_function_calls,
    loads_tool_json,
    make_open_probes,
    make_tasks,
    parse_args,
    parse_tool_args,
    render_event,
    render_completion_prompt,
    render_tool_response,
    render_existing_results_json,
    repo_root,
    resolve_completion_tool_call,
    resolve_completion_tool_format,
    resolve_output_dir,
    run_tasks,
)


class EmulatedFilesystemTests(unittest.TestCase):
    def test_rejects_absolute_and_parent_paths(self) -> None:
        env = EmulatedEnv(files={"safe.txt": "ok\n"})
        for path in ["/etc/passwd", "../safe.txt", "dir/../../safe.txt"]:
            with self.subTest(path=path):
                self.assertIn("ERROR: unsafe path", env.read_file({"path": path}))
                self.assertIn("ERROR: unsafe path", env.write_file({"path": path, "content": "x"}))

    def test_normalizes_relative_virtual_paths(self) -> None:
        env = EmulatedEnv(files={"src/answer.txt": "BLUE\n"})
        self.assertEqual(env.read_file({"path": "./src//answer.txt"}), "1: BLUE")

    def test_write_file_only_updates_virtual_filesystem(self) -> None:
        env = EmulatedEnv()
        old_cwd = os.getcwd()
        with tempfile.TemporaryDirectory() as tmp:
            os.chdir(tmp)
            try:
                self.assertEqual(env.write_file({"path": "created.txt", "content": "hello\n"}), "ok: wrote created.txt (1 lines)")
                self.assertEqual(env.files["created.txt"], "hello\n")
                self.assertFalse(Path("created.txt").exists())
            finally:
                os.chdir(old_cwd)

    def test_run_file_and_awk_are_emulated(self) -> None:
        env = EmulatedEnv(
            files={
                "hello.py": "print('host code is not executed')\n",
                "data.tsv": "name\tqty\tprice\napple\t3\t1.20\npear\t12\t0.75\n",
                "align.awk": "BEGIN { FS=\"\\t\" } { printf \"%-6s %2s %5s\\n\", $1, $2, $3 }\n",
            },
            run_outputs={"hello.py": "READY"},
            scenario="awk_tabs_justify",
        )
        self.assertIn("permission denied", env.run_file({"path": "hello.py"}))
        self.assertEqual(env.chmod({"path": "hello.py", "mode": "+x"}), "ok: mode rwx hello.py")
        self.assertEqual(env.run_file({"path": "hello.py"}), "READY")
        self.assertEqual(
            env.run_awk({"script_path": "align.awk", "input_path": "data.tsv"}),
            "name   qty price\napple   3  1.20\npear   12  0.75",
        )

    def test_run_tests_is_emulated(self) -> None:
        env = EmulatedEnv(
            files={"app.py": "def inc(x):\n    return x + 1\n"},
            scenario="run_tests_before_claim",
        )
        self.assertEqual(env.run_tests({}), "PASS\nincrement test passed")
        self.assertTrue(env.tests_passed)

    def test_run_lua_uses_emulated_files_and_exposes_io(self) -> None:
        env = EmulatedEnv(files={"numbers.csv": "value\n2\n3\n5\n"})
        result = env.run_lua(
            {
                "code": "local sum = 0\nfor n in FILES['numbers.csv']:gmatch('%d+') do sum = sum + tonumber(n) end\nprint(sum)"
            }
        )
        if "lua executable not found" in result:
            raise unittest.SkipTest("host lua is not installed")
        self.assertEqual(result, "10")
        self.assertEqual(env.run_lua({"code": "return type(io.open)"}), "function")
        self.assertIn("ERROR:", env.run_lua({"code": "return os.execute('true')"}))
        opened = env.run_lua(
            {
                "code": (
                    "local f = assert(io.open('numbers.csv', 'r'))\n"
                    "local sum = 0\n"
                    "for line in f:lines() do\n"
                    "  local n = tonumber(line)\n"
                    "  if n then sum = sum + n end\n"
                    "end\n"
                    "f:close()\n"
                    "print(sum)"
                )
            }
        )
        self.assertEqual(opened, "10")

    def test_hoist_nested_read_file_args(self) -> None:
        env = EmulatedEnv(files={"loan_terms.txt": "rate=1\n"})
        result = env.call(
            "read_file",
            {"command": "read_file", "args": {"path": "loan_terms.txt"}},
        )
        self.assertIn("rate=1", result)
        self.assertEqual(env.used_tools, ["read_file"])

    def test_alias_file_path_and_parameters_hoist(self) -> None:
        env = EmulatedEnv(files={"config.yml": "token: COBALT-7\n"}, expected_submit="COBALT-7")
        result = env.call("read_file", {"file_path": "config.yml"})
        self.assertIn("COBALT-7", result)
        submitted = env.call("submit", {"command": "submit", "parameters": {"answer": "COBALT-7"}})
        self.assertEqual(submitted, "submitted: COBALT-7")
        self.assertEqual(env.submitted, "COBALT-7")

    def test_shell_ls_unwraps_to_list_files(self) -> None:
        env = EmulatedEnv(files={"a.txt": "x\n"})
        result = env.call("bash", {"command": "ls -la"})
        self.assertIn("a.txt", result)
        self.assertEqual(env.used_tools, ["list_files"])
        self.assertEqual(env.unknown_tools, 0)
        env2 = EmulatedEnv(files={"b.txt": "y\n"})
        result2 = env2.call("bash", {"command": "ls"})
        self.assertEqual(result2, "b.txt")
        self.assertEqual(env2.used_tools, ["list_files"])

    def test_shell_ls_unwraps_to_ls_when_required(self) -> None:
        env = EmulatedEnv(files={"tool.py": "print(1)\n"}, required_tools=["ls", "chmod", "run_file", "submit"])
        result = env.call("run_shell", {"command": "ls"})
        self.assertIn("tool.py", result)
        self.assertEqual(env.used_tools, ["ls"])
        self.assertTrue(result.startswith("rw-") or "rw-" in result)

    def test_run_file_command_read_file_unwraps(self) -> None:
        env = EmulatedEnv(files={"sales.csv": "item,qty\napple,5\n"})
        result = env.call("run_file", {"command": "read_file", "path": "sales.csv"})
        self.assertIn("apple,5", result)
        self.assertEqual(env.used_tools, ["read_file"])
        env2 = EmulatedEnv(files={"hello.py": "print(1)\n"}, modes={"hello.py": "rw-"})
        result2 = env2.call(
            "run_file",
            {"command": "chmod", "args": ["+x", "hello.py"], "path": "hello.py"},
        )
        self.assertIn("ok: mode rwx", result2)
        self.assertEqual(env2.used_tools, ["chmod"])
        self.assertEqual(env2.mode_for("hello.py"), "rwx")

    def test_summarize_records_final_report(self) -> None:
        env = EmulatedEnv(files={"invoice.py": "x"})
        result = env.call("summarize", {"text": "Fixed tax to use post-discount base; tests PASS."})
        self.assertIn("recorded final answer", result)
        self.assertEqual(env.unknown_tools, 0)
        self.assertIn("post-discount", env.final_report or "")

    def test_run_file_nested_command_read_file_before_hoist(self) -> None:
        env = EmulatedEnv(files={"tickets/1842.md": "Amount requested: TWD 47.80\n"})
        result = env.call(
            "run_file",
            {"command": "read_file", "args": {"path": "tickets/1842.md"}},
        )
        self.assertIn("47.80", result)
        self.assertEqual(env.used_tools, ["read_file"])
        self.assertNotIn("permission denied", result.lower())

    def test_run_shell_comma_read_file_unwraps(self) -> None:
        env = EmulatedEnv(files={"bot_rates.tsv": "EUR\t36.845\n"}, required_tools=["read_file", "submit"])
        result = env.call("run_shell", {"command": "read_file, bot_rates.tsv"})
        self.assertIn("36.845", result)
        self.assertEqual(env.used_tools, ["read_file"])
        self.assertEqual(env.unknown_tools, 0)
        env2 = EmulatedEnv(files={"a.txt": "x\n"})
        result2 = env2.call("run_shell", {"command": "list_files, ."})
        self.assertIn("a.txt", result2)
        self.assertEqual(env2.used_tools, ["list_files"])

    def test_submit_answer_alias_counts_as_submit(self) -> None:
        env = EmulatedEnv(expected_submit="1", required_tools=["submit"])
        result = env.call("submit_answer", {"answer": "1"})
        self.assertEqual(result, "submitted: 1")
        self.assertEqual(env.submitted, "1")
        self.assertEqual(env.used_tools, ["submit"])
        self.assertEqual(env.unknown_tools, 0)

    def test_search_pattern_alias(self) -> None:
        env = EmulatedEnv(files={"parser.py": "def parse_date(text):\n    pass\n"})
        result = env.call("search", {"pattern": "parse_date"})
        self.assertIn("parser.py", result)

    def test_loads_tool_json_keeps_object_with_indexer(self) -> None:
        raw = '{"code": "local totals = {}\\nif totals[sku] then print(1) end"}'
        # Also with real newlines + Lua single-quote escapes like model output.
        raw_nl = '{"code": "local totals = {}\nif totals[sku] then\n  print(max_sku .. \' \' .. 1)\nend"}'
        obj, err = loads_tool_json(raw_nl)
        self.assertIsNone(err)
        self.assertIsInstance(obj, dict)
        self.assertIn("totals[sku]", obj["code"])

    def test_loads_tool_json_recovers_truncated_array(self) -> None:
        truncated = (
            '[\n  {\n    "type": "function",\n    "index": 0,\n'
            '    "name": "read_file",\n'
            '    "arguments": "{\\"path\\": \\"balance_schedule.csv\\"}"\n  }\n\n'
        )
        obj, err = loads_tool_json(truncated)
        self.assertIsNone(err)
        self.assertIsInstance(obj, list)
        self.assertEqual(obj[0]["name"], "read_file")

    def test_loads_tool_json_closes_truncated_object(self) -> None:
        truncated = (
            '{"command": "run_lua", "args": {"code": "local t=0\\nprint(t)"}'
        )
        obj, err = loads_tool_json(truncated)
        self.assertIsNone(err)
        self.assertIsInstance(obj, dict)
        self.assertEqual(obj["command"], "run_lua")
        self.assertIn("print(t)", obj["args"]["code"])

    def test_finish_after_submit_is_not_unknown(self) -> None:
        env = EmulatedEnv(expected_submit="BLUEBIRD", required_tools=["submit"])
        env.call("submit", {"answer": "BLUEBIRD"})
        result = env.call("finish", {"message": "done"})
        self.assertIn("recorded final answer", result)
        self.assertEqual(env.unknown_tools, 0)
        self.assertEqual(env.submitted, "BLUEBIRD")

    def test_run_lua_command_read_file_path_unwraps(self) -> None:
        env = EmulatedEnv(files={"orders.csv": "sku,qty\nSKU-17,3\n"})
        result = env.call("run_lua", {"command": "read_file orders.csv"})
        self.assertIn("SKU-17", result)
        self.assertEqual(env.used_tools, ["read_file"])

    def test_bash_write_and_app_prefix(self) -> None:
        env = EmulatedEnv(files={"config/local.env": "API_TIMEOUT=1\n"})
        result = env.call(
            "Bash",
            {"command": "write", "file_text": "API_TIMEOUT=45\n", "path": "/app/config/local.env"},
        )
        self.assertIn("ok: wrote", result)
        self.assertEqual(env.files["config/local.env"], "API_TIMEOUT=45\n")
        self.assertEqual(env.used_tools, ["write_file"])
        self.assertEqual(env.unknown_tools, 0)

    def test_submit_final_answer_alias(self) -> None:
        env = EmulatedEnv(expected_submit="28079.50")
        result = env.call("submit_final_answer", {"answer": "28079.50"})
        self.assertEqual(result, "submitted: 28079.50")
        self.assertEqual(env.used_tools, ["submit"])

    def test_extract_xml_function_calls(self) -> None:
        text = (
            "I'll read files.\n<functions>\n"
            "<function=read_file>\n<parameter=path>deploy.log</parameter>\n</function>\n"
            "<function=read_file>\n<parameter=path>worker.log</parameter>\n</function>\n"
            "</functions>"
        )
        calls = extract_xml_function_calls(text)
        self.assertIsNotNone(calls)
        assert calls is not None
        self.assertEqual(len(calls), 2)
        self.assertEqual(calls[0]["name"], "read_file")
        self.assertEqual(calls[0]["arguments"]["path"], "deploy.log")


class HostBoundaryTests(unittest.TestCase):
    def test_output_dir_defaults_under_repo(self) -> None:
        out_dir = resolve_output_dir(None, "test-run", False)
        self.assertTrue(out_dir.is_relative_to(repo_root()))
        self.assertEqual(out_dir.name, "test-run")

    def test_output_dir_rejects_outside_repo_without_opt_in(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(ValueError):
                resolve_output_dir(tmp, "ignored", False)
            self.assertEqual(resolve_output_dir(tmp, "ignored", True), Path(tmp).resolve())

    def test_html_escapes_event_text(self) -> None:
        rendered = render_event(Event(kind="assistant", title="Assistant", body="<script>alert(1)</script>"))
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", rendered)
        self.assertNotIn("<script>alert(1)</script>", rendered)

    def test_render_existing_results_json(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            results_path = tmp_path / "results.json"
            results_path.write_text(
                '{"run":{"model":"m","protocol":"chat","task":"t"},'
                '"results":[{"name":"t","title":"Task","passed":true,"score":1,'
                '"failures":[],"tool_calls":0,"turns":1,"final_answer":"ok",'
                '"events":[{"kind":"assistant","title":"Assistant","body":"ok","raw":null,"turn":1}]}]}',
                encoding="utf-8",
            )
            html_path = render_existing_results_json(results_path, tmp_path / "site")
            self.assertTrue(html_path.exists())
            self.assertIn("Primitive Bench", html_path.read_text(encoding="utf-8"))


class AgentCaseLoaderTests(unittest.TestCase):
    def test_default_benchmark_cases_load_from_files(self) -> None:
        tasks = make_tasks()
        self.assertGreaterEqual(len(tasks), 30)
        self.assertEqual(len(tasks), 130)
        self.assertIn("fx_column_trap", tasks)
        self.assertIn("final_checklist_item", tasks)
        env = tasks["fx_column_trap"].make_env()
        self.assertEqual(env.expected_submit, "28079.50")
        self.assertIn("orders.csv", env.files)

    def test_default_open_probe_cases_load_from_files(self) -> None:
        probes = make_open_probes()
        self.assertEqual(len(probes), 4)
        self.assertIn("host_inventory", probes)
        self.assertNotIn("submit", [tool["function"]["name"] for tool in probes["host_inventory"].tools])

    def test_custom_cases_folder_loads_direct_json_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            case_path = Path(tmp) / "one.json"
            case_path.write_text(
                '{"name":"one","title":"One","mode":"benchmark","system":"base",'
                '"prompt":"Read answer.txt and submit it.","tools":"nav",'
                '"environment":{"kind":"emulated","files":{"answer.txt":["OK"]},'
                '"expected_submit":"OK","required_tools":["read_file","submit"]},'
                '"evaluation":"submit","max_turns":4}',
                encoding="utf-8",
            )
            tasks = make_tasks(tmp)
            self.assertEqual(list(tasks), ["one"])
            self.assertEqual(tasks["one"].make_env().expected_submit, "OK")

    def test_parse_args_does_not_require_cases_to_exist(self) -> None:
        args = parse_args(["--cases", "does_not_exist", "--task", "made_up"])
        self.assertEqual(args.cases, "does_not_exist")
        self.assertEqual(args.task, "made_up")

    def test_default_http_timeout_allows_rwkv_parallel_queueing(self) -> None:
        args = parse_args([])
        self.assertEqual(args.timeout, 600.0)
        self.assertEqual(args.temperature, 0.001)

    def test_cases_py_plugin_loads_from_selected_folder(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            plugin = Path(tmp) / "cases.py"
            plugin.write_text(
                "def make_cases(api):\n"
                "    return [api.Task(\n"
                "        name='plugin_case', title='Plugin Case', mode='benchmark',\n"
                "        system=api.base_system(), prompt='Submit PLUGIN.',\n"
                "        tools=[api.SUBMIT_TOOL],\n"
                "        make_env=lambda: api.EmulatedEnv(expected_submit='PLUGIN', required_tools=['submit']),\n"
                "        score=api.score_submit, max_turns=3,\n"
                "    )]\n",
                encoding="utf-8",
            )
            tasks = make_tasks(tmp)
            self.assertEqual(list(tasks), ["plugin_case"])
            self.assertEqual(tasks["plugin_case"].make_env().expected_submit, "PLUGIN")


class ParallelRunTests(unittest.TestCase):
    def test_parallel_results_keep_task_order(self) -> None:
        class FakeClient:
            def chat(self, payload):
                prompt = payload["messages"][1]["content"]
                if "first" in prompt:
                    time.sleep(0.02)
                return {"choices": [{"message": {"role": "assistant", "content": prompt, "tool_calls": []}}]}

        def score(env, events, final, tool_calls):
            _ = env
            _ = events
            _ = tool_calls
            return bool(final), 1.0 if final else 0.0, [] if final else ["empty final"]

        selected = [
            Task("first", "First", "first", [], "system", EmulatedEnv, score, max_turns=1),
            Task("second", "Second", "second", [], "system", EmulatedEnv, score, max_turns=1),
        ]
        results = run_tasks(
            FakeClient(),
            selected,
            n_parallel=2,
            max_turns=None,
            temperature=0.0,
            top_p=1.0,
            thinking_temperature=None,
            thinking_top_p=None,
            max_tokens=16,
            reasoning_budget_tokens=None,
            protocol="chat",
            completion_tool_format=COMPLETION_TOOL_FORMATS["g1h"],
            completion_force_action=False,
        )
        self.assertEqual([result.name for result in results], ["first", "second"])


class SynchronousBatchClientTests(unittest.TestCase):
    def test_coalesces_prompts_and_demultiplexes_sse_choices(self) -> None:
        requests = []

        class FakeResponse:
            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

            def __iter__(self):
                return iter(
                    [
                        b'data: {"choices":[{"index":1,"delta":{"content":"B"}}]}\n',
                        b'data: {"choices":[{"index":0,"delta":{"content":"A"}}]}\n',
                        b'data: {"choices":[{"index":1,"delta":{"content":"2"}},{"index":0,"delta":{"content":"1"}}]}\n',
                        b'data: [DONE]\n',
                    ]
                )

        def fake_urlopen(request, timeout):
            _ = timeout
            requests.append(json.loads(request.data.decode("utf-8")))
            return FakeResponse()

        client = SynchronousBatchClient(
            "http://localhost:8000/v1",
            "rwkv7-g1i",
            10,
            password="secret",
            top_k=50,
            alpha_presence=0.0,
            alpha_frequency=0.0,
            alpha_decay=0.99,
            chunk_size=4,
            batch_wait=0.05,
            backend="rwkv_lightning",
        )
        barrier = threading.Barrier(2)

        def complete(prompt):
            barrier.wait()
            return client.complete(
                {
                    "prompt": prompt,
                    "n_predict": 16,
                    "temperature": 0.0,
                    "top_p": 0.6,
                    "stop": ["<tool_call>", "\n\nUser:"],
                    "stream": False,
                }
            )["content"]

        try:
            with mock.patch("primitive_bench.urllib.request.urlopen", side_effect=fake_urlopen):
                with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
                    outputs = list(executor.map(complete, ["prompt-a", "prompt-b"]))
        finally:
            client.close()

        self.assertEqual(len(requests), 1)
        self.assertEqual(set(requests[0]["contents"]), {"prompt-a", "prompt-b"})
        response_by_prompt = dict(zip(requests[0]["contents"], ["A1", "B2"]))
        self.assertEqual(outputs, [response_by_prompt["prompt-a"], response_by_prompt["prompt-b"]])
        self.assertEqual(requests[0]["stop_tokens"], ["</tool_call>", "\n\nUser:"])
        self.assertEqual(requests[0]["temperature"], 0.001)
        self.assertTrue(requests[0]["stream"])
        self.assertEqual(requests[0]["password"], "secret")


class CompletionProtocolTests(unittest.TestCase):
    def test_g1i_auto_format_and_prompt(self) -> None:
        tool_format = resolve_completion_tool_format("rwkv7-g1i-preview", "auto")
        self.assertEqual(tool_format.name, "g1i")
        prompt = render_completion_prompt(
            "Use tools when needed.",
            "Multiply 2 by 3.",
            [
                {
                    "type": "function",
                    "function": {
                        "name": "multiply",
                        "description": "Multiply two numbers.",
                        "parameters": {
                            "type": "object",
                            "properties": {
                                "a": {"type": "number", "description": "First factor"},
                                "b": {"type": "number"},
                            },
                        },
                    },
                }
            ],
            tool_format,
        )
        # Official BlinkDL G1x: Tools: [...] + Return only a JSON function call + ```json prime
        self.assertIn("System: Tools:\n[", prompt)
        self.assertIn('"name":"multiply"', prompt)
        self.assertIn('"arguments":{', prompt)
        self.assertIn('"a":{"type":"number"', prompt)
        self.assertNotIn('"parameters"', prompt)
        self.assertNotIn("</functions>", prompt)
        self.assertIn("Return only a JSON function call.", prompt)
        self.assertTrue(prompt.endswith("User: Multiply 2 by 3.\n\nAssistant: ```json\n"))
        self.assertEqual(tool_format.trigger, "<tool_call>")

    def test_g1i_tool_response_variants_are_descriptor_defined(self) -> None:
        tool_format = COMPLETION_TOOL_FORMATS["g1i"]
        self.assertEqual(
            render_tool_response(tool_format, ["42"]),
            "\n\nUser: Function output:\n42\n\nAssistant: ```json\n",
        )
        self.assertEqual(
            render_tool_response(tool_format, ["first", "second"], plural=True),
            "\n\nUser: Function output:\nfirst\nsecond\n\nAssistant: ```json\n",
        )

    def test_resolve_completion_tool_call_flat_name_args(self) -> None:
        name, args, err = resolve_completion_tool_call(
            {"name": "read_file", "args": {"path": "sales.csv"}}
        )
        self.assertIsNone(err)
        self.assertEqual(name, "read_file")
        self.assertEqual(args, {"path": "sales.csv"})
        name2, args2, err2 = resolve_completion_tool_call(
            {"function": {"name": "submit", "arguments": "{\"answer\": \"42\"}"}}
        )
        self.assertIsNone(err2)
        self.assertEqual(name2, "submit")
        self.assertEqual(args2, {"answer": "42"})

    def test_resolve_completion_tool_call_name_inside_arguments(self) -> None:
        name, args, err = resolve_completion_tool_call(
            {
                "function": {
                    "arguments": '{"name": "read_file", "args": {"path": "sales.csv"}}',
                    "type": "function",
                },
                "index": -1,
            }
        )
        self.assertIsNone(err)
        self.assertEqual(name, "read_file")
        self.assertEqual(args, {"path": "sales.csv"})


if __name__ == "__main__":
    unittest.main()
