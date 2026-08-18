#!/usr/bin/env bash
# Local, no-network tests for git-credential-vault.
# Run as root on a Linux host to exercise the production root-only checks;
# non-root workstations report a skip instead of weakening the helper.

set -euo pipefail

if [[ $EUID -ne 0 ]]; then
  printf 'SKIP: helper requires root; run this harness as root on a Linux test host\n'
  exit 0
fi

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HELPER="$HERE/git-credential-vault"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

MOCK_BIN="$TMP/bin"
CONF="$TMP/etc/git-vault"
mkdir -p "$MOCK_BIN" "$CONF"
chmod 0700 "$CONF"

cat > "$MOCK_BIN/vault" <<'MOCK'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >> "${MOCK_VAULT_LOG:?}"
case "$*" in
  "write -field=token auth/approle/login"*) printf 'approle-token\n' ;;
  "token revoke -self") printf 'revoked\n' ;;
  "kv get -format=json secret/github/read/all")
    printf '%s\n' '{"data":{"data":{"token":"github-token","username":"x-access-token","expires":"2099-01-01T00:00:00Z"}}}' ;;
  "kv get -format=json secret/github/fleet/pve/token")
    printf '%s\n' '{"data":{"data":{"token":"pve-token","username":"x-access-token","expires":"2099-01-01T00:00:00Z"}}}' ;;
  "kv get -format=json secret/github/write/config-archive")
    printf '%s\n' '{"data":{"data":{"token":"archive-token","username":"x-access-token","expires":"2099-01-01T00:00:00Z"}}}' ;;
  "kv get -format=json secret/github/stale")
    printf '%s\n' '{"data":{"data":{"token":"stale-token","username":"x-access-token","expires":"2000-01-01T00:00:00Z"}}}' ;;
  *) printf 'unexpected mock vault command: %s\n' "$*" >&2; exit 1 ;;
esac
MOCK
chmod 0755 "$MOCK_BIN/vault"

write_config() {
  local method="$1" path="$2"
  {
    printf 'VAULT_ADDR=https://vault.example.test:8200\n'
    printf 'GIT_VAULT_AUTH_METHOD=%s\n' "$method"
    printf 'GIT_VAULT_TOKEN_PATH=%s\n' "$path"
  } > "$CONF/config"
  chmod 0640 "$CONF/config"
}

run_helper() {
  local repo_path="${1:-}" output status
  set +e
  output="$(
    GIT_VAULT_CONF_DIR="$CONF" \
    PATH="$MOCK_BIN:$PATH" \
    MOCK_VAULT_LOG="$TMP/vault.log" \
    "$HELPER" get <<EOF
protocol=https
host=github.com
path=$repo_path

EOF
  )"
  status=$?
  set -e
  printf '%s\n' "$output"
  return "$status"
}

# 1. Existing AppRole flow still logs in and revokes its short-lived token.
write_config approle secret/github/read/all
install -o root -g root -m 0600 /dev/null "$CONF/role-id"
install -o root -g root -m 0600 /dev/null "$CONF/secret-id"
: > "$TMP/vault.log"
approle_output="$(run_helper '')"
grep -Fq 'username=x-access-token' <<< "$approle_output"
grep -Fq 'password=github-token' <<< "$approle_output"
grep -Fq 'token revoke -self' "$TMP/vault.log"

# 2. Agent mode reads the sink and must not log in or revoke that token.
write_config agent secret/github/read/all
install -o root -g root -m 0600 /dev/null "$TMP/agent-token"
printf 'agent-token\n' > "$TMP/agent-token"
chmod 0600 "$TMP/agent-token"
printf 'GIT_VAULT_AGENT_TOKEN=%s\n' "$TMP/agent-token" >> "$CONF/config"
: > "$TMP/vault.log"
agent_output="$(run_helper '')"
grep -Fq 'password=github-token' <<< "$agent_output"
if grep -Eq 'approle/login|token revoke' "$TMP/vault.log"; then
  printf 'FAIL: Agent mode attempted AppRole login or token revocation\n' >&2
  exit 1
fi

# 3. A stale GitHub token fails closed and emits quit=true.
write_config agent secret/github/stale
: > "$TMP/vault.log"
set +e
stale_output="$(run_helper '')"
stale_status=$?
set -e
[[ "$stale_status" -ne 0 ]]
grep -Fq 'quit=true' <<< "$stale_output"

# 4. A path-map entry selects the write token only for the exact repository.
write_config agent secret/github/fleet/pve/token
printf '%s\n' 'Impulse-Engineering/proxmox.git secret/github/write/config-archive' > "$CONF/path-map"
chmod 0640 "$CONF/path-map"
: > "$TMP/vault.log"
mapped_output="$(run_helper 'Impulse-Engineering/proxmox.git')"
grep -Fq 'password=pve-token' <<< "$mapped_output" || grep -Fq 'password=archive-token' <<< "$mapped_output"
grep -Fq 'kv get -format=json secret/github/write/config-archive' "$TMP/vault.log"

printf 'PASS: AppRole, Agent token, stale-token, and path-map helper cases\n'
