# What SetupLens can read

## Supported inputs

| File | Extraction | Important limits |
| --- | --- | --- |
| `package.json` | Engines, package manager, scripts, install/preparation hooks, direct URL dependency notes | No lockfile/dependency tree analysis; whether hooks run depends on the package manager and settings |
| `pyproject.toml` | `project.requires-python`, `project.scripts`, `build-system.build-backend` | No Poetry-specific metadata, dependency resolution or backend inspection |
| `setup.py` | Literal Python constraint, `cmdclass`, selected literal subprocess/os.system calls | Syntax only; no imports, evaluation, alias resolution, reachability or execution |
| `Cargo.toml` | Rust version/edition and default or custom build-script reference, respecting `build = false` | No dependency build scripts or workspace inheritance resolution |
| Referenced Rust build script | Literal single-line `Command::new("tool")` references | Lexical only; no argument-chain reconstruction, macros, aliases, block-comment parsing or reachability |
| `Dockerfile`, `Dockerfile.*` | Base image, `EXPOSE`, selected command patterns | No build, multistage resolution, ARG substitution or image inspection; EXPOSE does not publish a port |
| `compose.yaml/yml`, `docker-compose.yaml/yml` | Simple two-space service mappings, image and block-form port settings, selected options | No full YAML parser; anchors, interpolation, merges, includes, alternative indentation and inline lists can be missed or misattributed |
| `.sh`, `.bash`, `.ps1`, `.cmd`, `.bat` | Selected command patterns and simple continuations | No full shell/PowerShell parser; quoted text, heredocs and dynamic commands can mislead heuristics |
| `Makefile`, `Justfile` | Simple target declarations and selected command patterns | Targets are source declarations, not expanded executable instructions or a dependency graph |
| Root `.github/workflows/*.yml/yaml` | Action ref pinning, broad permissions, selected command patterns | Lexical only; no reusable workflow resolution or effective permission computation |
| `.env.example`, `.env.sample`, `.env.template`, `example.env`, `sample.env` | Assignment names only | Values are omitted; names alone do not prove that a service or credential is required |

Nested projects are inspected within scan limits. SetupLens does not read README instructions, ordinary application source (except explicitly referenced Rust build scripts), lockfiles, real `.env` files, generated code or downloaded artifacts. Cross-ecosystem support here means partial declaration extraction across these formats, not full semantic understanding of each ecosystem.

## Review rules

Priority indicates what to read first. None of these rules proves malicious intent.

| ID | Priority | Review topic |
| --- | --- | --- |
| SL001 | Medium | npm install/preparation lifecycle hook |
| SL002 | High | Download piped to a shell or PowerShell evaluation |
| SL003 | Medium | Elevated privileges requested |
| SL004 | Medium | Recursive deletion |
| SL005 | Medium | World-writable permission mode |
| SL006 | High | Privileged container |
| SL007 | High | Docker control socket reference |
| SL008 | Medium | Unencrypted HTTP download |
| SL009 | Medium | Direct Git/URL dependency |
| SL010 | Info | Python build backend |
| SL011 | Medium | Compose published-port block |
| SL012 | High | Host networking |
| SL013 | High | GitHub token `write-all` permissions |
| SL014 | Medium | Action ref not pinned to a full commit SHA |
| SL015 | Info | Executable Python setup entry point |
| SL016 | Medium | Custom Python build/install command classes |
| SL017 | Info | Rust build-time script |

Normal development can produce many of these notes. For example, deleting a build cache can trigger SL004 and a local PostgreSQL port can trigger SL011. Read the evidence and suggested check rather than counting warnings as a risk score.

## Bounds and source locations

- At most 256 KiB per supported file, 500 inspected files, 20,000 directory entries and directory depth 12.
- Oversized, unreadable, binary-looking and non-UTF-8 files produce coverage notes.
- Default skipped directories: `.git`, `.hg`, `.svn`, `node_modules`, `.venv`, `venv`, `env`, `vendor`, `dist`, `build`, `target`, `.next`, `coverage`, `__pycache__`, `.tox`, `.cache`; other hidden directories are skipped except `.github`.
- User exclusions match directory components or `pathlib` relative path globs. They also apply to referenced Cargo build scripts.
- Source lines for JSON/TOML declarations are located by matching keys. Repeated keys, quoted TOML keys and unusual formatting may fall back to the first match or line 1. Python syntax-tree line numbers and line-based rules are more direct.
- An entry-count limit can make the subset depend on filesystem enumeration order; ordinary scans within the limits are sorted and deterministic.
- `--strict` treats skipped or unparsed inputs and empty coverage as incomplete. Standard lexical-scope notes are explanatory and do not trigger strict mode. This flag cannot detect every unsupported construct.

## Format references

The scope above is an implementation boundary, not a restatement of the full specifications:

- [npm scripts and lifecycle behavior](https://docs.npmjs.com/cli/using-npm/scripts/)
- [Python pyproject metadata](https://packaging.python.org/en/latest/guides/writing-pyproject-toml/)
- [Cargo build scripts](https://doc.rust-lang.org/cargo/reference/build-scripts.html)
- [Compose services](https://docs.docker.com/reference/compose-file/services/)
