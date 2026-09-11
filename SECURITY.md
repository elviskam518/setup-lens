# Trust boundaries

SetupLens is a static onboarding aid, not a sandbox, malware verdict or authorization to run a repository.

The scanner reads a bounded selection of local files. It does not import target modules, invoke a shell, start subprocesses, fetch dependencies or make network requests. Python's AST parser inspects `setup.py` syntax only. No Git commands or package manager commands run against a target.

Symlinks and Windows reparse points are skipped and checked again before reading. This does not protect against a hostile process concurrently replacing paths. Scan a stable checkout; use operating-system isolation if the filesystem itself is actively adversarial. The Python interpreter and SetupLens installation remain trusted components.

Real environment files are not scan inputs. Supported environment templates contribute names only. Common credential-shaped strings elsewhere are masked on a best-effort basis, not comprehensively removed. A report can expose file names, commands, service names, internal URLs or secrets in unsupported formats.

HTML escapes repository-derived text and includes a restrictive Content Security Policy with no external connections. It uses inline CSS and JavaScript for local filtering. The tool writes reports only when requested; existing files need `--force`, and known scanned files, environment filenames, symlinks/reparse destinations and hard-linked outputs are rejected. These checks are not a defense against concurrent filesystem mutation.

Findings are heuristics. Missing findings do not establish safety. Read the source, check the [coverage boundary](docs/coverage.md), and use dedicated dependency and vulnerability tools when those are the questions you need answered.

Once the project has a public repository, maintainers should enable GitHub private vulnerability reporting. Until a private reporting channel exists, do not post exploitable details or credentials in public issues. No monitored private address is claimed by this source release.
