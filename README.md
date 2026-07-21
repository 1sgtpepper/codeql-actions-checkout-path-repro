# actions-checkout path analysis fixture

Public, fork-only reproduction for
[`github/codeql#22213`](https://github.com/github/codeql/issues/22213).

The workflow fixtures compare default and alternate `actions/checkout` paths
across Linux, Windows, macOS, `bash`, `sh`, `pwsh`, nested and quoted paths,
local actions, and `workflow_run`. CI executes the runtime-compatible matrix,
analyzes the workflow files, and uploads focused SARIF and JSON alert evidence.
The expected matrix records the observed shell distinction: `bash` and `sh`
reproduce total alternate-path suppression, while `pwsh` receives the `high`
fallback for both default and alternate paths.

[`evidence/expected-matrix.json`](evidence/expected-matrix.json) records the
expected behavior on an affected CodeQL release. `scripts/summarize_sarif.py`
extracts one default-path positive control and one expected-critical-but-missing
alternate-path case while retaining the full SARIF as a CI artifact.
