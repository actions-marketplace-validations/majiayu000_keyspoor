# Check a pull request and stop a local commit

Keyspoor can check a repository in CI and scan staged files before a local
commit. CI checks the checked-out files. The local hook checks the Git index,
so unstaged edits cannot hide a credential that is about to be committed.

## Copy one workflow file

Copy [the complete workflow](../examples/github-actions/keyspoor.yml) to
`.github/workflows/keyspoor.yml` in your repository and commit it. It runs on
pull requests, pushes and manual dispatches with only `contents: read`.
It does not run your project's install scripts or build your application.
The scanner Action installs its published npm package; network access to npm
is needed during installation, while scanning runs locally.

The `Keyspoor / secrets` job fails when the scanner finds a credential or cannot
finish scanning. Its `keyspoor-report` artifact remains available after a scan
failure and expires after seven days. An installation failure may occur before
a report is created. Select that job as a required status check in your branch
protection or ruleset after its first run.

| Scanner exit code | Meaning | Next step |
| --- | --- | --- |
| `0` | Selected scope completed without reported findings | Merge if other checks pass. |
| `1` | Selected scope completed with findings | Download the report, inspect the path/line and fix or review each finding. |
| `2` | Error or incomplete scan | Fix the error and rerun; a partial report does not establish that the scope is clean. |

Reports contain redacted findings and no raw secret or source snippet. They
still contain paths, rule names and fingerprints. An artifact is a report to
review; uploading it does not create a GitHub secret-scanning alert.

Change `path: .` to an existing application directory such as `src` to scan
only that directory. Expand the scope once existing findings have been
reviewed. Filesystem scans respect ignore files by default and always exclude
Git metadata. This workflow does not check local Git history, LFS objects or
submodule contents that have not been checked out. For those scopes, use the
CLI explicitly rather than assuming a deeper checkout changes Action mode.

The template follows the maintained `majiayu000/keyspoor@v1` ref. Pin it to a
reviewed full commit SHA when your policy requires immutable Actions. The
checkout and artifact Actions already use full SHAs, as recommended by
[GitHub's security guidance](https://docs.github.com/en/actions/reference/security/secure-use).

## Optional: show SARIF in GitHub code scanning

The artifact workflow works without code scanning. If your repository supports
code scanning, add the following permissions under the `secrets` job and append
the upload step after the artifact step:

```yaml
    permissions:
      contents: read
      actions: read
      security-events: write
```

```yaml
      - name: Upload complete analysis to code scanning
        if: >-
          always() && github.event_name != 'pull_request' &&
          (steps.scan.outputs.exit-code == '0' || steps.scan.outputs.exit-code == '1')
        uses: github/codeql-action/upload-sarif@7999b86c43a865dc79d8923397f35af22de63401 # v4
        with:
          sarif_file: ${{ steps.scan.outputs.report-path }}
          category: keyspoor-files
```

This upload runs on pushes and manual dispatches only; all pull requests,
including forks, keep the read-only artifact flow. Do not switch to
`pull_request_target` to gain write permissions for fork code. GitHub may
require approval before running a first-time contributor's fork workflow.
Private/internal repository code scanning requires the applicable GitHub Code
Security entitlement and enabled repository settings. See
[GitHub's SARIF upload documentation](https://docs.github.com/en/code-security/how-tos/find-and-fix-code-vulnerabilities/integrate-with-existing-tools/upload-sarif-file).
An upload failure remains a job failure; the artifact still holds the report.

## Add a local Git pre-commit hook

Install the CLI once, for example with `npm install -g keyspoor`, and verify
`keyspoor --version`. Git must be able to find `keyspoor` in the environment
used by your terminal or Git GUI.

Find your hook location with `git rev-parse --git-path hooks/pre-commit`.
Create that file with the following contents, then make it executable with
`chmod +x "$(git rev-parse --git-path hooks/pre-commit)"`. If you already have a
hook, incorporate the scan into it rather than replacing its other checks.
This uses Git's configured hook directory, including `core.hooksPath`.

```sh
#!/bin/sh
if ! command -v keyspoor >/dev/null 2>&1; then
  echo 'Keyspoor is unavailable. Install it and rerun the commit.' >&2
  exit 2
fi
exec keyspoor staged . --format jsonl
```

Code `1` or `2` blocks the commit. Git hooks are local and can be bypassed, so
the CI status check remains the shared enforcement point. Test the hook with
`"$(git rev-parse --git-path hooks/pre-commit)"` before your first commit.
The hook scans entire changed index files, not just added lines; a pre-existing
credential in a staged file can also block the commit.

## Start with existing findings

Review a full initial report first. Keyspoor reports patterns; it does not
contact credential providers or establish whether credentials are active.
Handle confirmed credentials according to their provider's revocation process.
For CI, the current Action has only `path` and `format` inputs: it has no
baseline input. Start with a reviewed directory via `path` or resolve existing
findings before making the complete repository scan required.

For repeated CLI scans in the **same local checkout**, save a baseline after
reviewing findings. Store it in Git metadata, outside the scanned files:

```sh
baseline_path="$(git rev-parse --git-path keyspoor-files-baseline.json)"
keyspoor scan . --write-baseline "$baseline_path"
keyspoor scan . --baseline "$baseline_path"
```

Writing a baseline still returns `1` when findings exist; confirm the scan
completed and the file was written. The second command suppresses the saved
fingerprints and reports new findings. A changed credential value remains a
new finding. Do not repeatedly rewrite the baseline to turn failing scans green.

A staged hook needs its own **staged** baseline:

```sh
staged_baseline="$(git rev-parse --git-path keyspoor-staged-baseline.json)"
keyspoor staged . --write-baseline "$staged_baseline"
keyspoor staged . --baseline "$staged_baseline" --format jsonl
```

Create it from the exact index contents you have reviewed, then use the second
command in your existing hook if you choose this policy. A filesystem baseline
cannot be used for staged or history scans. Baselines bind the canonical
checkout path, scan mode, ignore policy, size budget, rules and fingerprint key
identity. Copying a local baseline into a fresh CI checkout will usually cause
an identity mismatch and exit `2`; it is not a portable CI suppression list.
Use a separate reviewed baseline after an intentional change of scope or policy.
An incomplete scan cannot create or replace a baseline.

## Verify your setup

Use an isolated scratch repository and a synthetic token. Never paste a real
credential into a test:

```sh
scratch_dir="$(mktemp -d)"
git -C "$scratch_dir" init -q
printf 'ordinary configuration\n' > "$scratch_dir/config.txt"
keyspoor scan "$scratch_dir" --format sarif
# Expected exit: 0.
python3 - "$scratch_dir/config.txt" <<'PY'
import pathlib, sys
synthetic = 'ghp_' + 'A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8'
pathlib.Path(sys.argv[1]).write_text('token = "' + synthetic + '"\n')
PY
keyspoor scan "$scratch_dir" --format sarif
# Expected exit: 1, with a redacted github-pat finding.
git -C "$scratch_dir" add config.txt
printf 'ordinary configuration\n' > "$scratch_dir/config.txt"
keyspoor staged "$scratch_dir" --format jsonl
# Expected exit: 1, because the index still contains the synthetic token.
keyspoor scan "$scratch_dir/missing.txt" --format sarif
# Expected exit: 2, with executionSuccessful false in SARIF.
```

For the workflow, push the same clean and synthetic examples to a temporary
repository using the copied file. Check that the clean commit passes, the
synthetic commit fails and the failed run still exposes a redacted artifact.
Remove the temporary repository when the exercise is complete. The project's
[published Action smoke workflow](../.github/workflows/action-smoke.yml)
separately checks clean, finding and missing-input behavior across runner OSes.
