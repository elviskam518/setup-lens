"""Bounded, read-only inspection. Never import or run code from the target."""

from __future__ import annotations

import ast
import hashlib
import json
import os
import re
import stat
import tomllib
from dataclasses import asdict, dataclass, field
from pathlib import Path

from . import __version__

IGNORED = {".git", ".hg", ".svn", "node_modules", ".venv", "venv", "env", "vendor", "dist", "build", "target", ".next", "coverage", "__pycache__", ".tox", ".cache"}
MAX_BYTES = 262_144
MAX_FILES = 500
MAX_ENTRIES = 20_000
MAX_DEPTH = 12
PRIORITIES = {"high": 0, "medium": 1, "info": 2}
LIFECYCLE = {"preinstall", "install", "postinstall", "prepublish", "preprepare", "prepare", "postprepare"}
SOURCE_EXTENSIONS = {".sh", ".bash", ".ps1", ".cmd", ".bat"}
ENV_TEMPLATES = {".env.example", ".env.sample", ".env.template", "example.env", "sample.env"}
SENSITIVE = re.compile(r"(?i)(?:password|passwd|secret|token|api[_-]?key|credential|private[_-]?key)")


def redact(text: str) -> str:
    """Best-effort display masking, never a guarantee of secret removal."""
    text = re.sub(r"(?i)(https?://)[^\s/@:]+:[^\s/@]+@", r"\1[redacted]@", text)
    text = re.sub(r"(?i)(Bearer\s+)[\w.\-]+", r"\1[redacted]", text)
    text = re.sub(r"(?i)((?:[\w.-]*(?:password|passwd|secret|token|api[_-]?key|credential)[\w.-]*)[\"']?\s*[:=]\s*)([\"'])(.*?)\2", r"\1\2[redacted]\2", text)
    text = re.sub(r"(?i)((?:[\w.-]*(?:password|passwd|secret|token|api[_-]?key|credential)[\w.-]*)\s*=\s*)(?![\"'])[^\s,;]+", r"\1[redacted]", text)
    return "".join(c if c in "\n\t" or ord(c) >= 32 and ord(c) != 127 else "?" for c in text)


def without_comment(line: str) -> str:
    """Remove shell/YAML-style comments outside simple quoted strings."""
    quote = None
    escaped = False
    for i, char in enumerate(line):
        if escaped:
            escaped = False
        elif char == "\\" and quote != "'":
            escaped = True
        elif quote:
            if char == quote:
                quote = None
        elif char in "\"'":
            quote = char
        elif char == "#" and (i == 0 or line[i - 1].isspace()):
            return line[:i]
    return line


@dataclass
class Finding:
    rule: str
    priority: str
    title: str
    path: str
    line: int
    evidence: str
    why: str
    action: str
    fingerprint: str = ""

    def __post_init__(self):
        # Use masked evidence: reports must not contain secret-dependent hashes.
        self.evidence = redact(self.evidence).strip()[:600]
        raw = f"{self.rule}|{self.path}|{self.evidence}"
        self.fingerprint = hashlib.sha256(raw.encode()).hexdigest()[:16]


@dataclass
class Report:
    project: str
    version: str = __version__
    schema_version: int = 1
    files: list[str] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    runtimes: list[dict] = field(default_factory=list)
    commands: list[dict] = field(default_factory=list)
    services: list[dict] = field(default_factory=list)
    environment: list[dict] = field(default_factory=list)
    ecosystems: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        result = asdict(self)
        result["summary"] = {p: sum(f.priority == p for f in self.findings) for p in PRIORITIES}
        return result


class Scanner:
    def __init__(self, root: Path, excludes: tuple[str, ...] = (), max_files: int = MAX_FILES):
        self.root = root.resolve()
        if not self.root.is_dir():
            raise ValueError("Scan target must be an existing directory.")
        self.excludes = excludes
        self.max_files = max_files
        self.report = Report(project=redact(self.root.name))
        self.seen: set[tuple] = set()
        self.entries = 0
        self.stopped = False

    def note(self, text: str):
        text = redact(text)
        if text not in self.report.notes:
            self.report.notes.append(text)

    def add(self, rule, priority, title, path, line, evidence, why, action):
        f = Finding(rule, priority, title, path, line, evidence, why, action)
        key = (f.rule, f.path, f.line, f.evidence)
        if key not in self.seen:
            self.seen.add(key)
            self.report.findings.append(f)

    def kind(self, relative: Path) -> str | None:
        name = relative.name.lower()
        if name in ENV_TEMPLATES:
            return "environment"
        if name == "package.json":
            return "package"
        if name == "pyproject.toml":
            return "python"
        if name == "setup.py":
            return "setup_python"
        if name == "cargo.toml":
            return "cargo"
        if name in {"compose.yml", "compose.yaml", "docker-compose.yml", "docker-compose.yaml"}:
            return "compose"
        if name == "dockerfile" or name.startswith("dockerfile."):
            return "docker"
        if relative.suffix.lower() in {".yml", ".yaml"} and relative.parts[:2] == (".github", "workflows"):
            return "workflow"
        if relative.suffix.lower() in SOURCE_EXTENSIONS:
            return "script"
        if name in {"makefile", "justfile"}:
            return "script"
        return None

    def walk(self, directory: Path, depth: int = 0):
        if depth > MAX_DEPTH:
            self.note(f"Directory depth limit ({MAX_DEPTH}) reached; some files were not inspected.")
            return
        try:
            # Bound directory enumeration too; never materialize an unbounded tree.
            with os.scandir(directory) as iterator:
                entries = []
                for entry in iterator:
                    self.entries += 1
                    if self.entries > MAX_ENTRIES:
                        self.stopped = True
                        self.note(f"Entry limit ({MAX_ENTRIES}) reached; scan is incomplete.")
                        break
                    entries.append(entry)
            for entry in sorted(entries, key=lambda e: e.name):
                if len(self.report.files) >= self.max_files:
                    self.stopped = True
                    self.note(f"File limit ({self.max_files}) reached; scan may be incomplete.")
                    return
                path = Path(entry.path)
                rel = path.relative_to(self.root)
                if any(rel.match(pattern) or any(part == pattern for part in rel.parts) for pattern in self.excludes):
                    continue
                try:
                    st = entry.stat(follow_symlinks=False)
                    if entry.is_symlink() or getattr(st, "st_file_attributes", 0) & 0x400:
                        self.note(f"Skipped link/reparse point: {rel.as_posix()}")
                        continue
                    if stat.S_ISDIR(st.st_mode):
                        if entry.name in IGNORED or entry.name.startswith(".") and entry.name != ".github":
                            continue
                        self.walk(path, depth + 1)
                        if self.stopped:
                            return
                    elif stat.S_ISREG(st.st_mode):
                        kind = self.kind(rel)
                        if kind:
                            yield_path = (path, rel.as_posix(), kind, st.st_size)
                            self.inspect(*yield_path)
                except OSError:
                    self.note(f"Could not inspect: {rel.as_posix()}")
        except OSError:
            self.note(f"Could not list directory: {directory.relative_to(self.root).as_posix()}")

    def inspect(self, path: Path, rel: str, kind: str, size: int):
        if rel in self.report.files:
            return
        if len(self.report.files) >= self.max_files:
            self.note(f"File limit ({self.max_files}) reached; scan may be incomplete.")
            return
        if size > MAX_BYTES:
            self.note(f"Skipped oversized file (>256 KiB): {rel}")
            return
        # Re-check immediately before reading. This is not a sandbox against a
        # hostile process changing the directory concurrently; see SECURITY.md.
        if path.is_symlink() or not path.resolve().is_relative_to(self.root) or any(p.exists() and getattr(p.lstat(), "st_file_attributes", 0) & 0x400 for p in (path, *path.parents)):
            self.note(f"Skipped changed/outside path: {rel}")
            return
        try:
            with path.open("rb") as handle:
                raw = handle.read(MAX_BYTES + 1)
            if len(raw) > MAX_BYTES:
                self.note(f"Skipped growing file: {rel}")
                return
            if b"\0" in raw:
                self.note(f"Skipped binary-looking file: {rel}")
                return
            text = raw.decode("utf-8-sig")
        except (OSError, UnicodeError):
            self.note(f"Skipped unreadable/non-UTF-8 file: {rel}")
            return
        self.report.files.append(rel)
        try:
            getattr(self, f"parse_{kind}")(text, rel)
        except (json.JSONDecodeError, tomllib.TOMLDecodeError, ValueError, RecursionError, SyntaxError):
            self.note(f"Could not parse {rel}; its contents were not fully inspected.")

    def line_for(self, text: str, key: str) -> int:
        pattern = re.compile(r'(?<!\\)"' + re.escape(key) + r'"\s*:')
        match = pattern.search(text)
        return text.count("\n", 0, match.start()) + 1 if match else 1

    def runtime(self, name: str, value, rel: str, line: int = 1):
        self.report.runtimes.append({"name": name, "value": redact(str(value)), "path": rel, "line": line})

    def ecosystem(self, name: str):
        if name not in self.report.ecosystems:
            self.report.ecosystems.append(name)

    def literal_line(self, text: str, key: str) -> int:
        match = re.search(r"(?m)^\s*" + re.escape(key) + r"\s*=", text)
        return text.count("\n", 0, match.start()) + 1 if match else 1

    def parse_package(self, text: str, rel: str):
        self.ecosystem("Node.js")
        data = json.loads(text)
        if not isinstance(data, dict):
            raise ValueError("package must be an object")
        engines = data.get("engines", {})
        if isinstance(engines, dict):
            for name, value in engines.items():
                self.runtime(str(name), value, rel, self.line_for(text, str(name)))
        if isinstance(data.get("packageManager"), str):
            self.runtime("package manager", data["packageManager"], rel, self.line_for(text, "packageManager"))
        scripts = data.get("scripts", {})
        if not isinstance(scripts, dict):
            self.note(f"Unexpected scripts value in {rel}.")
            scripts = {}
        # JSON decoding retains real command text, including escaped newlines.
        for name, command in scripts.items():
            if not isinstance(command, str):
                continue
            line = self.line_for(text, name)
            self.report.commands.append({"name": name, "command": redact(command), "path": rel, "line": line, "automatic": name in LIFECYCLE})
            if name in LIFECYCLE:
                self.add("SL001", "medium", "Install lifecycle hook", rel, line, f'{name}: {command}', "This script can run during package installation or preparation, depending on the package manager and its settings.", "Read this command and any scripts it invokes before installing. Check your package manager's lifecycle controls.")
            self.command_rules(command, rel, line)
        for field_name in ("dependencies", "devDependencies", "optionalDependencies"):
            deps = data.get(field_name, {})
            if not isinstance(deps, dict):
                continue
            for name, value in deps.items():
                if isinstance(value, str) and re.match(r"(?:git\+|git://|github:|https?://)", value):
                    self.add("SL009", "medium", "Dependency fetched outside the registry", rel, self.line_for(text, name), f'{name}: {value}', "A direct Git or URL dependency needs a separate provenance and revision check.", "Review its source and pin an immutable revision or verified artifact where possible.")

    def parse_python(self, text: str, rel: str):
        self.ecosystem("Python")
        data = tomllib.loads(text)
        project = data.get("project", {})
        build = data.get("build-system", {})
        if isinstance(project, dict):
            if "requires-python" in project:
                self.runtime("Python", project["requires-python"], rel, self.literal_line(text, "requires-python"))
            scripts = project.get("scripts", {})
            if isinstance(scripts, dict):
                for name, value in scripts.items():
                    if isinstance(value, str):
                        self.report.commands.append({"name": str(name), "command": redact(value), "path": rel, "line": self.literal_line(text, str(name)), "automatic": False})
        if isinstance(build, dict) and "build-backend" in build:
            line = self.literal_line(text, "build-backend")
            self.runtime("Python build backend", build["build-backend"], rel, line)
            self.add("SL010", "info", "Python build backend", rel, line, str(build["build-backend"]), "Building a Python source distribution invokes its build backend. SetupLens does not import or inspect backend code.", "Review build-system requirements and backend source when building an unfamiliar project.")

    def parse_setup_python(self, text: str, rel: str):
        self.ecosystem("Python")
        tree = ast.parse(text, filename=rel)
        self.add("SL015", "info", "Executable Python setup entry point", rel, 1, "setup.py", "This file is Python code. Build tools may invoke it; SetupLens parses syntax without importing or evaluating it.", "Review custom build commands and dynamic configuration. Prefer declared metadata when onboarding.")
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            fn = ast.unparse(node.func)
            if fn in {"setup", "setuptools.setup", "distutils.core.setup"}:
                for kw in node.keywords:
                    if kw.arg == "python_requires" and isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, str):
                        self.runtime("Python", kw.value.value, rel, kw.value.lineno)
                    if kw.arg == "cmdclass":
                        self.add("SL016", "medium", "Custom Python build/install commands", rel, kw.value.lineno, ast.get_source_segment(text, kw.value) or "cmdclass", "The package overrides build or installation commands. Their behavior is not resolved here.", "Read the referenced command classes before building the package.")
            if fn in {"os.system", "subprocess.run", "subprocess.call", "subprocess.check_call", "subprocess.check_output", "subprocess.Popen"} and node.args:
                value = node.args[0]
                if isinstance(value, ast.Constant) and isinstance(value.value, str):
                    command = value.value
                elif isinstance(value, (ast.List, ast.Tuple)) and all(isinstance(v, ast.Constant) and isinstance(v.value, str) for v in value.elts):
                    command = " ".join(v.value for v in value.elts)
                else:
                    command = "[dynamic command — inspect source]"
                self.report.commands.append({"name": f"{fn} call (reachability unknown)", "command": redact(command), "path": rel, "line": node.lineno, "automatic": False})
                self.command_rules(command, rel, node.lineno)

    def parse_cargo(self, text: str, rel: str):
        self.ecosystem("Rust")
        data = tomllib.loads(text)
        package = data.get("package", {})
        if not isinstance(package, dict):
            raise ValueError("package must be a table")
        for key, label in (("rust-version", "Rust"), ("edition", "Rust edition")):
            if key in package:
                self.runtime(label, package[key], rel, self.literal_line(text, key))
        if "package" not in data or package.get("build") is False:
            return
        build_name = package.get("build", "build.rs")
        if build_name is True:
            build_name = "build.rs"
        if not isinstance(build_name, str):
            return
        path = self.root / Path(rel).parent / build_name
        if not path.resolve().is_relative_to(self.root):
            self.note(f"Rust build script leaves scan root in {rel}; it was not read.")
            return
        build_rel = path.relative_to(self.root).as_posix()
        # Respect excludes and default ignored directories for referenced files.
        parts = Path(build_rel).parts
        if any(part in IGNORED for part in parts) or any(Path(build_rel).match(p) or p in parts for p in self.excludes):
            self.note(f"Rust build script excluded: {build_rel}")
            return
        if not path.is_file():
            if "build" in package:
                self.note(f"Declared Rust build script missing: {build_rel}")
            return
        line = self.literal_line(text, "build")
        self.report.commands.append({"name": "Cargo build script", "command": build_rel, "path": rel, "line": line, "automatic": True})
        self.add("SL017", "info", "Rust build-time script", rel, line, build_rel, "Cargo compiles and runs this build script before building the package. It may generate code or build native libraries.", "Read the build script and check any native tools it calls. Dependencies may have their own build scripts outside this scan.")
        try:
            self.inspect(path, build_rel, "rust_build", path.stat().st_size)
        except OSError:
            self.note(f"Could not inspect Rust build script: {build_rel}")

    def parse_rust_build(self, text: str, rel: str):
        self.note("Rust build-script inspection only extracts literal Command::new calls; macros, aliases and dynamic arguments are not resolved.")
        # Lexical references are explicitly labeled; presence is not reachability.
        for n, raw in enumerate(text.splitlines(), 1):
            line = raw.strip()
            if line.startswith("//"):
                continue
            match = re.search(r'\bCommand::new\(\s*"([^"\n]+)"\s*\)', line)
            if match:
                self.report.commands.append({"name": "Rust process reference (reachability unknown)", "command": redact(match[1]), "path": rel, "line": n, "automatic": False})

    def command_rules(self, command: str, rel: str, line: int):
        checks = [
            ("SL002", "high", "Downloaded code piped into a shell", r"(?is)\b(?:curl|wget|iwr|irm|Invoke-WebRequest|Invoke-RestMethod)\b[^\n]*(?:\|\s*(?:sudo\s+)?(?:ba|da|z|k)?sh\b|\|\s*(?:iex|Invoke-Expression)\b)", "This command runs content returned by a network request.", "Download and inspect the script first; verify the source and a pinned checksum or release."),
            ("SL003", "medium", "Elevated command", r"(?i)(?:^|[\s;&|])sudo\s+|\bStart-Process\b[^\n]*-Verb\s+RunAs\b", "This command requests administrator privileges.", "Check what needs elevation and whether it can run with fewer permissions."),
            ("SL004", "medium", "Recursive deletion command", r"(?i)\brm\s+(?:-[a-z]+\s+)*-[a-z]*r[a-z]*\b|\bRemove-Item\b[^\n]*-Recurse\b|\brmdir\s+/s\b", "This command recursively deletes a path. A build-folder cleanup may be intentional.", "Check the exact target, variable expansion and working directory before running it."),
            ("SL005", "medium", "World-writable permissions", r"(?i)\bchmod\s+(?:-[a-zA-Z]+\s+)*0?777\b", "Mode 777 grants read, write and execute permissions to everyone.", "Use the narrowest permissions that the setup actually needs."),
            ("SL006", "high", "Privileged container", r"(?i)(?:\bprivileged\s*:\s*true\b|--privileged(?:\s|$|=true))", "Privileged containers receive broad access to the host.", "Identify the required capabilities and prefer specific grants over privileged mode."),
            ("SL007", "high", "Docker control socket reference", r"(?:/var/run|/run)/docker\.sock|docker_engine", "A Docker socket can let a container or process control the host's Docker daemon. Read-only socket mounts do not make its API read-only.", "Check why daemon control is needed and isolate the workload from sensitive hosts."),
            ("SL008", "medium", "Unencrypted download URL", r"(?i)\b(?:curl|wget|iwr|irm|Invoke-WebRequest|Invoke-RestMethod)\b[^\n]*http://", "This download uses HTTP, which does not authenticate or encrypt the transport.", "Use an authenticated HTTPS source and verify the downloaded artifact."),
        ]
        for rule, priority, title, pattern, why, action in checks:
            if re.search(pattern, command):
                self.add(rule, priority, title, rel, line, command, why, action)

    def parse_script(self, text: str, rel: str):
        if Path(rel).name.lower() in {"makefile", "justfile"}:
            self.ecosystem("Task recipes")
            for n, raw in enumerate(text.splitlines(), 1):
                match = re.match(r"^([A-Za-z_][\w.-]*)(?:\s+[^:=]+)?\s*:(?!=)(.*)$", raw)
                if match:
                    self.report.commands.append({"name": match[1], "command": without_comment(raw).strip(), "path": rel, "line": n, "automatic": False})
        chunks = []
        start = 1
        for number, raw in enumerate(text.splitlines(), 1):
            line = without_comment(raw).strip()
            if not line or line.lower().startswith(("rem ", "::")):
                continue
            if not chunks:
                start = number
            continued = line.endswith(("\\", "`", "^"))
            chunks.append(line[:-1] if continued else line)
            if not continued:
                self.command_rules(" ".join(chunks), rel, start)
                chunks = []
        if chunks:
            self.command_rules(" ".join(chunks), rel, start)

    def parse_docker(self, text: str, rel: str):
        self.ecosystem("Docker")
        self.parse_script(text, rel)
        for n, raw in enumerate(text.splitlines(), 1):
            line = without_comment(raw).strip()
            match = re.match(r"(?i)FROM\s+(?:--platform=\S+\s+)?(\S+)", line)
            if match:
                self.runtime("container base", match[1], rel, n)
            match = re.match(r"(?i)EXPOSE\s+(.+)", line)
            if match:
                self.report.services.append({"name": "Container port metadata", "value": redact(match[1]), "path": rel, "line": n})

    def parse_compose(self, text: str, rel: str):
        self.ecosystem("Docker")
        self.note("Compose and workflow inspection is lexical: anchors, merges, interpolation and included files are not resolved.")
        self.parse_script(text, rel)
        current_service = "Container"
        in_services = False
        ports_indent = None
        for n, raw in enumerate(text.splitlines(), 1):
            clean = without_comment(raw).rstrip()
            if not clean.strip():
                continue
            indent = len(clean) - len(clean.lstrip())
            line = clean.strip()
            if indent == 0:
                in_services = line == "services:"
            if in_services and indent == 2 and re.fullmatch(r"[\w.-]+:", line):
                current_service = line[:-1]
            if re.match(r"image\s*:", line):
                value = line.split(":", 1)[1].strip(" \"'")
                self.report.services.append({"name": current_service, "value": redact(value), "path": rel, "line": n})
            if ports_indent is not None and indent <= ports_indent:
                ports_indent = None
            if re.match(r"ports\s*:", line):
                ports_indent = indent
                self.add("SL011", "medium", "Ports published to the host", rel, n, line, "A Compose ports block publishes container ports. Actual binding depends on its values and Compose configuration.", "Inspect host IP and port values. Bind local-only services explicitly to 127.0.0.1 when appropriate.")
            elif ports_indent is not None:
                self.report.services.append({"name": f"{current_service} · port setting", "value": redact(line), "path": rel, "line": n})
            if re.match(r"network_mode\s*:\s*[\"']?host\b", line):
                self.add("SL012", "high", "Host network requested", rel, n, line, "Host network mode removes normal container network isolation on supported platforms.", "Confirm host networking is required and review listening services.")
            if "&" in line or line.startswith("<<:") or re.match(r"(?:include|extends)\s*:", line):
                self.note(f"Compose indirection in {rel}:{n}; effective configuration may differ from this report.")

    def parse_workflow(self, text: str, rel: str):
        self.note("Compose and workflow inspection is lexical: anchors, merges, interpolation and included files are not resolved.")
        self.parse_script(text, rel)
        for n, raw in enumerate(text.splitlines(), 1):
            line = without_comment(raw).strip()
            if re.search(r"permissions\s*:\s*[\"']?write-all\b", line):
                self.add("SL013", "high", "Broad GitHub token permissions", rel, n, line, "write-all grants broad write permissions to the workflow token, subject to repository and event restrictions.", "Declare only the specific permissions the job needs.")
            match = re.match(r"(?:-\s*)?uses\s*:\s*[\"']?([^\s\"']+)", line)
            if match and not match[1].startswith(("./", "docker://")):
                ref = match[1].rsplit("@", 1)[-1]
                if not re.fullmatch(r"[0-9a-fA-F]{40}", ref):
                    self.add("SL014", "medium", "Action is not pinned to a commit", rel, n, line, "A tag or branch can point to different action code later.", "Review the action and pin its full commit SHA; retain the release tag in a comment for readability.")

    def parse_environment(self, text: str, rel: str):
        for n, raw in enumerate(text.splitlines(), 1):
            match = re.match(r"\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=", raw)
            if match:
                self.report.environment.append({"name": match[1], "sensitive_name": bool(SENSITIVE.search(match[1])), "path": rel, "line": n})

    def scan(self) -> Report:
        self.walk(self.root)
        self.report.findings.sort(key=lambda f: (PRIORITIES[f.priority], f.path, f.line, f.rule))
        if not self.report.files:
            self.note("No supported setup files found. This is not a clean bill of health.")
        return self.report


def scan(root: str | Path, *, excludes: tuple[str, ...] = (), max_files: int = MAX_FILES) -> Report:
    return Scanner(Path(root), excludes, max_files).scan()
