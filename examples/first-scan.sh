#!/bin/sh
# Run in a disposable repository; requires Git and an installed Keyspoor CLI.
set -eu
fail() { printf '%s\n' "$*" >&2; exit 2; }
scanner=$(command -v keyspoor) || fail 'Install Keyspoor first: npm install -g keyspoor@0.1.4'
command -v git >/dev/null 2>&1 || fail 'Git is required for this demo.'
case "$scanner" in /*) ;; *) fail 'Keyspoor must resolve to an absolute executable path.' ;; esac
demo_dir=$(mktemp -d "${TMPDIR:-/tmp}/keyspoor-demo.XXXXXX")
trap 'rm -rf "$demo_dir"' EXIT
trap 'exit 2' HUP INT TERM
# Isolate user hooks, signing and identity settings from the demonstration.
export GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null
unset GIT_DIR GIT_WORK_TREE GIT_INDEX_FILE GIT_CONFIG_COUNT GIT_CONFIG_PARAMETERS
export GIT_AUTHOR_NAME='Keyspoor demo' GIT_AUTHOR_EMAIL='demo@example.invalid'
export GIT_COMMITTER_NAME="$GIT_AUTHOR_NAME" GIT_COMMITTER_EMAIL="$GIT_AUTHOR_EMAIL"
git init -q --template= "$demo_dir"
cd "$demo_dir"
mkdir -p .git/hooks
export KEYSPOOR_DEMO_SCANNER="$scanner"
cat >.git/hooks/pre-commit <<'HOOK'
#!/bin/sh
"$KEYSPOOR_DEMO_SCANNER" staged . --format json >.git/keyspoor-report.json
status=$?
printf 'Keyspoor pre-commit: exit=%s\n' "$status"
exit "$status"
HOOK
chmod +x .git/hooks/pre-commit
# A deliberately invented value, never printed by this script.
printf 'password=KspDemo_7zQ2mX9pL4vN6sR8\n' >settings.env
git add settings.env
printf '1. Scan the staged synthetic credential\n'
status=0
"$scanner" staged . --format json >.git/keyspoor-report.json || status=$?
[ "$status" -eq 1 ] || fail "Expected finding exit=1; got exit=$status."
cat .git/keyspoor-report.json
printf '\n2. Attempt a commit with the finding\n'
status=0
git -c core.hooksPath=.git/hooks -c commit.gpgsign=false commit -q -m 'demo finding' >.git/commit.log 2>&1 || status=$?
cat .git/commit.log
[ "$status" -eq 1 ] || fail "Expected blocked commit exit=1; got exit=$status."
[ "$(cat .git/commit.log)" = 'Keyspoor pre-commit: exit=1' ] || fail 'Commit failed for a reason other than the finding.'
if git rev-parse --verify HEAD >/dev/null 2>&1; then fail 'The finding was committed unexpectedly.'; fi
printf '\n3. Remove the literal and stage the repair\n'
printf 'password=${APP_PASSWORD}\n' >settings.env
git add settings.env
"$scanner" staged . --format json >.git/keyspoor-report.json
cat .git/keyspoor-report.json
printf '\n4. Commit the repaired file\n'
git -c core.hooksPath=.git/hooks -c commit.gpgsign=false commit -q -m 'demo repair'
git rev-parse --verify HEAD >/dev/null
printf 'PASS: finding detected, commit blocked, repair scanned clean, commit accepted.\n'
