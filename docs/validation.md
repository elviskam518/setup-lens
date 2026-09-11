# Validation for 0.1.0

Checked locally on Windows with Python 3.12.14 on 2026-09-12.

| Check | Observed result |
| --- | --- |
| `python -m unittest discover -s tests -v` | 43 tests discovered: 42 passed, 1 skipped |
| Symlink behavior test | Skipped because this Windows session cannot create symlinks; no passing claim for that case |
| Source CLI demo | HTML and JSON produced; 8 files, 10 command declarations, 6 environment names |
| Four ecosystem inventory | Node.js, Python, Rust and Docker detected; Make targets also appear under Task recipes |
| Offline wheel build | Built with existing setuptools, `--no-index --no-build-isolation --no-deps` |
| Wheel install | Installed with `--no-index --no-deps` into an isolated temporary target |
| Installed-package smoke check | Imported outside the source tree; generated the same HTML byte-for-byte, including packaged CSS/JS |
| Browser controls | High-priority filter showed 1 of 7 findings; no-match search showed 0 of 7; clearing filters restored 7 of 7 |
| Source inventory navigation | Check-your-tools link navigated to the runtime inventory |
| Responsive inspection | Desktop and 390px viewport checked visually; mobile document width did not exceed its viewport |
| Browser log inspection | No warning/error entries returned during the check |

The GitHub Actions matrix is configured for Windows, Ubuntu and macOS with Python 3.11–3.13. Those remote jobs have not been run as part of this local release. No real-world accuracy benchmark, exhaustive accessibility audit, print/PDF validation or security audit has been performed. The demo is intentionally fictional and is never started or installed.

The shipped tests include malformed inputs, dynamic setup declarations, excluded directories, hard-linked output protection, HTML/Markdown injection payloads, source location checks, environment-value omission, deterministic reports and a non-execution fixture.
