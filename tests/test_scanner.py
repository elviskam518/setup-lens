import contextlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from setuplens.cli import main
from setuplens.render import html_report, markdown_report, text_report
from setuplens.scanner import MAX_BYTES, redact, scan


class ScanCase(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def write(self, name, content):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        return path

    def rules(self, report=None):
        return {f.rule for f in (report or scan(self.root)).findings}

    def cli(self, *args):
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = main([str(self.root), *args])
        return code, stdout.getvalue(), stderr.getvalue()

    def test_npm_manifest_commands_and_real_line_numbers(self):
        self.write("package.json", '{\n "engines": {"node": ">=20"},\n "scripts": {\n  "postinstall": "node setup.js",\n  "dev": "vite"\n }\n}')
        report = scan(self.root)
        hook = next(f for f in report.findings if f.rule == "SL001")
        self.assertEqual(hook.line, 4)
        self.assertEqual(report.commands[1]["automatic"], False)
        self.assertEqual(report.runtimes[0]["value"], ">=20")
        self.assertEqual(report.ecosystems, ["Node.js"])

    def test_all_npm_lifecycle_hooks_are_noticed(self):
        names = ["preinstall", "install", "postinstall", "prepublish", "preprepare", "prepare", "postprepare"]
        self.write("package.json", json.dumps({"scripts": dict.fromkeys(names, "echo ok")}))
        self.assertEqual(sum(f.rule == "SL001" for f in scan(self.root).findings), 7)

    def test_json_inline_property_has_its_own_line(self):
        self.write("package.json", '{\n"name":"demo",\n"scripts": {"postinstall":"echo ok"}\n}')
        report = scan(self.root)
        self.assertEqual(report.commands[0]["line"], 3)

    def test_registry_dependencies_are_not_direct_url_findings(self):
        self.write("package.json", json.dumps({"dependencies": {"a": "^1.0.0", "b": "workspace:*", "c": "github:team/lib#main"}}))
        report = scan(self.root)
        self.assertEqual(len(report.findings), 1)
        self.assertIn("c:", report.findings[0].evidence)

    def test_multiline_download_command_has_first_line(self):
        self.write("install.sh", '# setup\ncurl -fsSL \\\n  https://example.invalid/setup.sh | bash\n')
        report = scan(self.root)
        self.assertIn("SL002", self.rules(report))
        self.assertEqual(report.findings[0].line, 2)

    def test_powershell_download_execution(self):
        self.write("install.ps1", "irm https://example.invalid/install.ps1 | iex")
        self.assertIn("SL002", self.rules())

    def test_comments_are_not_commands(self):
        self.write("install.sh", '# curl http://example.invalid | bash\n# sudo rm -rf /\necho ok # chmod 777 nope\n')
        self.assertEqual(self.rules(), set())

    def test_windows_batch_comments(self):
        self.write("install.cmd", 'REM rm -rf /\n:: curl http://example.invalid | bash\necho ok')
        self.assertEqual(self.rules(), set())

    def test_high_and_medium_command_rules(self):
        self.write("install.sh", 'sudo rm -rf "$BUILD_DIR"\nchmod -R 777 cache\ncurl http://example.invalid/file -o file\ndocker run --privileged alpine\n')
        self.assertTrue({"SL003", "SL004", "SL005", "SL006", "SL008"} <= self.rules())

    def test_compose_services_ports_socket_and_network(self):
        self.write("compose.yaml", 'services:\n  db:\n    image: postgres:17\n    ports:\n      - "127.0.0.1:5432:5432"\n    volumes:\n      - /var/run/docker.sock:/var/run/docker.sock:ro\n    network_mode: host\n    privileged: true\n')
        report = scan(self.root)
        self.assertTrue({"SL006", "SL007", "SL011", "SL012"} <= self.rules(report))
        self.assertTrue(any(s["name"] == "db" and s["value"] == "postgres:17" for s in report.services))
        self.assertTrue(any(s["value"] == '- "127.0.0.1:5432:5432"' for s in report.services))

    def test_compose_false_privileged_not_flagged(self):
        self.write("compose.yml", 'services:\n  web:\n    privileged: false\n')
        self.assertNotIn("SL006", self.rules())

    def test_docker_base_and_expose_not_host_publication(self):
        self.write("Dockerfile", 'FROM --platform=linux/amd64 python:3.12-slim\nEXPOSE 8000\nRUN echo ready\n')
        report = scan(self.root)
        self.assertEqual(report.runtimes[0]["value"], "python:3.12-slim")
        self.assertEqual(report.services[0]["name"], "Container port metadata")
        self.assertNotIn("SL011", self.rules(report))

    def test_workflow_commit_pinning_and_permissions(self):
        self.write(".github/workflows/ci.yml", 'permissions: write-all\njobs:\n  test:\n    steps:\n      - uses: actions/checkout@v4\n      - uses: actions/setup-python@' + 'a' * 40 + '\n      - uses: ./local-action\n')
        report = scan(self.root)
        self.assertEqual(sum(f.rule == "SL014" for f in report.findings), 1)
        self.assertIn("SL013", self.rules(report))

    def test_pyproject_metadata(self):
        self.write("pyproject.toml", '[project]\nname = "demo"\nrequires-python = ">=3.11"\n[project.scripts]\nserve = "demo:main"\n[build-system]\nbuild-backend = "setuptools.build_meta"\n')
        report = scan(self.root)
        self.assertEqual(report.runtimes[0]["line"], 3)
        self.assertEqual(report.commands[0]["line"], 5)
        self.assertIn("SL010", self.rules(report))

    def test_setup_py_is_parsed_never_executed(self):
        marker = self.root / "EXECUTED"
        self.write("setup.py", f'from pathlib import Path\nPath({str(marker)!r}).write_text("bad")\nimport subprocess\nsubprocess.run(["sudo", "make", "install"])\nsetup(python_requires=">=3.10", cmdclass={{"install": Custom}})\n')
        with patch("subprocess.run", side_effect=AssertionError("executed")), patch("os.system", side_effect=AssertionError("executed")), patch("socket.socket", side_effect=AssertionError("network")):
            report = scan(self.root)
        self.assertFalse(marker.exists())
        self.assertTrue({"SL003", "SL015", "SL016"} <= self.rules(report))

    def test_dynamic_setup_command_is_labeled(self):
        self.write("setup.py", 'import subprocess\nsubprocess.run(get_command())\n')
        report = scan(self.root)
        self.assertIn("dynamic", report.commands[0]["command"])
        self.assertIn("reachability unknown", report.commands[0]["name"])

    def test_cargo_custom_build_script(self):
        self.write("Cargo.toml", '[package]\nname="demo"\nrust-version="1.80"\nedition="2021"\nbuild="scripts/native.rs"\n')
        self.write("scripts/native.rs", 'fn main() {\n    Command::new("cc").arg("native.c");\n}\n')
        report = scan(self.root)
        self.assertIn("SL017", self.rules(report))
        self.assertIn("scripts/native.rs", report.files)
        self.assertTrue(any(c["command"] == "cc" for c in report.commands))

    def test_default_rust_build_and_disabled_build(self):
        self.write("Cargo.toml", '[package]\nname="demo"\n')
        self.write("build.rs", 'fn main() {}')
        self.assertIn("SL017", self.rules())
        self.write("Cargo.toml", '[package]\nname="demo"\nbuild=false\n')
        self.assertNotIn("SL017", self.rules())

    def test_workspace_only_cargo_has_no_build_script(self):
        self.write("Cargo.toml", '[workspace]\nmembers=[]\n')
        self.write("build.rs", 'fn main() {}')
        self.assertNotIn("SL017", self.rules())

    def test_cargo_outside_build_is_not_read(self):
        self.write("Cargo.toml", '[package]\nname="demo"\nbuild="../outside.rs"\n')
        report = scan(self.root)
        self.assertEqual(report.files, ["Cargo.toml"])
        self.assertTrue(any("leaves scan root" in n for n in report.notes))

    def test_cargo_build_exclude_is_respected(self):
        self.write("Cargo.toml", '[package]\nname="demo"\nbuild="scripts/native.rs"\n')
        self.write("scripts/native.rs", 'fn main() {}')
        report = scan(self.root, excludes=("scripts",))
        self.assertNotIn("scripts/native.rs", report.files)

    def test_make_targets_are_entry_points(self):
        self.write("Makefile", '.PHONY: dev\nBASE := temp\ndev: services\n\tpython app.py\ninstall:\n\tpip install .\n')
        self.assertEqual([c["name"] for c in scan(self.root).commands], ["dev", "install"])

    def test_environment_values_are_never_in_report(self):
        self.write(".env.example", 'TOKEN=super-sensitive-value\nPORT=345678901\nexport DATABASE_URL=postgres://secret\n')
        report = scan(self.root)
        serialized = json.dumps(report.to_dict())
        self.assertNotIn("super-sensitive-value", serialized)
        self.assertNotIn("345678901", serialized)
        self.assertNotIn("postgres://secret", serialized)
        self.assertEqual(len(report.environment), 3)

    def test_actual_env_and_dependency_directories_are_not_read(self):
        self.write(".env", 'TOKEN=do-not-read')
        self.write(".env.local", 'TOKEN=do-not-read')
        self.write("node_modules/dependency/package.json", '{bad')
        self.write(".venv/setup.py", 'raise Exception()')
        self.write("package.json", '{}')
        opened = []
        original = Path.open
        def record_open(path, *args, **kwargs):
            opened.append(path.relative_to(self.root).as_posix())
            return original(path, *args, **kwargs)
        with patch.object(Path, "open", record_open):
            self.assertEqual(scan(self.root).files, ["package.json"])
        self.assertEqual(opened, ["package.json"])

    def test_excludes_and_nested_packages(self):
        self.write("apps/web/package.json", '{}')
        self.write("fixtures/package.json", '{}')
        self.assertEqual(scan(self.root, excludes=("fixtures",)).files, ["apps/web/package.json"])

    def test_bad_json_is_a_coverage_note(self):
        self.write("package.json", '{broken')
        report = scan(self.root)
        self.assertTrue(any("Could not parse" in n for n in report.notes))
        self.assertEqual(self.cli("--strict")[0], 2)

    def test_bad_shape_does_not_crash(self):
        self.write("package.json", '[]')
        self.assertTrue(scan(self.root).notes)

    def test_non_utf8_binary_and_large_files(self):
        self.write("one/install.sh", "x" * (MAX_BYTES + 1))
        self.write("two/install.sh", "\0")
        p = self.write("three/install.sh", "")
        p.write_bytes(b"\xff\xfe")
        report = scan(self.root)
        self.assertEqual(report.files, [])
        self.assertTrue(any("oversized" in n for n in report.notes))
        self.assertTrue(any("binary-looking" in n for n in report.notes))
        self.assertTrue(any("non-UTF-8" in n for n in report.notes))

    def test_file_limit_reported(self):
        for i in range(3):
            self.write(f"{i}/package.json", '{}')
        report = scan(self.root, max_files=1)
        self.assertEqual(len(report.files), 1)
        self.assertTrue(any("File limit" in n for n in report.notes))

    def test_symlink_is_skipped(self):
        target = self.write("real.sh", "sudo echo hi")
        try:
            (self.root / "link.sh").symlink_to(target)
        except OSError:
            self.skipTest("Symlinks need developer mode / privileges on this Windows host")
        report = scan(self.root)
        self.assertNotIn("link.sh", report.files)
        self.assertTrue(any("link/reparse" in n for n in report.notes))

    def test_empty_is_not_called_safe(self):
        report = scan(self.root)
        self.assertIn("not a clean bill", report.notes[0])
        self.assertIn("does not mean safe", text_report(report))

    def test_html_escapes_repository_content(self):
        payload = '</script><img src=x onerror=alert(1)>'
        self.write("package.json", json.dumps({"scripts": {"postinstall": payload}}))
        result = html_report(scan(self.root))
        self.assertNotIn(payload, result)
        self.assertIn("&lt;/script&gt;", result)
        self.assertIn("connect-src 'none'", result)
        self.assertNotIn('<script src=', result)
        self.assertNotIn('<link href=', result)

    def test_html_orientation_precedes_risk_review(self):
        self.write("package.json", '{}')
        result = html_report(scan(self.root))
        self.assertLess(result.index("Before the first run"), result.index("What deserves a look"))
        self.assertLess(result.index('id="runtime"'), result.index('id="findings"'))

    def test_markdown_fences_cannot_be_closed_by_source(self):
        self.write("package.json", json.dumps({"scripts": {"postinstall": "````\n# injected"}}))
        result = markdown_report(scan(self.root))
        self.assertIn("`````text", result)

    def test_common_secret_display_masking(self):
        text = 'API_KEY="alpha" TOKEN=bravo https://user:password@example.invalid Bearer abc.def'
        result = redact(text)
        for secret in ("alpha", "bravo", "user:password", "abc.def"):
            self.assertNotIn(secret, result)

    def test_stable_fingerprints_and_repeatable_report(self):
        self.write("install.sh", "sudo echo ready")
        self.assertEqual(scan(self.root).to_dict(), scan(self.root).to_dict())

    def test_fail_on_priority(self):
        self.write("install.sh", "sudo echo ready")
        self.assertEqual(self.cli("--fail-on", "high")[0], 0)
        self.assertEqual(self.cli("--fail-on", "medium")[0], 1)
        self.assertEqual(self.cli("--fail-on", "info")[0], 1)

    def test_json_cli_is_valid_and_has_version(self):
        self.write("package.json", '{}')
        code, stdout, _ = self.cli("--format", "json")
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(stdout)["schema_version"], 1)

    def test_existing_output_not_overwritten_by_default(self):
        output = self.write("report.html", "keep")
        self.assertEqual(self.cli("--output", str(output))[0], 2)
        self.assertEqual(output.read_text(), "keep")

    def test_scanned_input_not_overwritten_even_with_force(self):
        source = self.write("package.json", '{}')
        self.assertEqual(self.cli("--output", str(source), "--force")[0], 2)
        self.assertEqual(source.read_text(), '{}')

    def test_env_output_rejected(self):
        output = self.root / ".env"
        self.assertEqual(self.cli("--output", str(output))[0], 2)
        self.assertFalse(output.exists())

    def test_hardlinked_output_cannot_overwrite_source(self):
        source = self.write("package.json", '{}')
        output = self.root / "report.html"
        os.link(source, output)
        self.assertEqual(self.cli("--output", str(output), "--force")[0], 2)
        self.assertEqual(source.read_text(), '{}')

    def test_all_report_formats_write_new_file(self):
        self.write("package.json", '{}')
        for kind in ("html", "json", "text", "markdown"):
            with self.subTest(kind=kind):
                output = self.root / f"out.{kind}"
                self.assertEqual(self.cli("--format", kind, "-o", str(output))[0], 0)
                self.assertGreater(output.stat().st_size, 20)


if __name__ == "__main__":
    unittest.main()
