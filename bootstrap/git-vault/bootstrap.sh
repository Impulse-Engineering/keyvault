#!/usr/bin/env bash
# bootstrap.sh — prepare a Linux host for Vault-brokered GitHub HTTPS access.
#
# PUBLIC repo. This script contains no secrets and expects none: the AppRole
# credential files are delivered out-of-band by an operator (see the private
# vault repo's RUNBOOK-GITHUB-ACCESS.md).
#
# What it does (idempotent, re-runnable, root):
#   1. Installs the HashiCorp Vault CLI (Debian/apt or RHEL-family/dnf) and
#      MASKS vault.service — these hosts are Vault clients, never servers.
#   2. Writes /etc/git-vault/config (VAULT_ADDR, fleet token path).
#   3. Installs the git-credential-vault helper (sha256-verified against the
#      hash reviewed into THIS script) and scopes it to github.com only.
#   4. --ssh-key: optional SSH fallback transport (see below).
#
# Supply chain: ALWAYS fetch this script and the helper pinned to a commit
# SHA, never a branch:
#   C=<reviewed commit sha>
#   curl -fsSLO https://raw.githubusercontent.com/Impulse-Engineering/keyvault/$C/bootstrap/git-vault/bootstrap.sh
#   curl -fsSLO https://raw.githubusercontent.com/Impulse-Engineering/keyvault/$C/bootstrap/git-vault/git-credential-vault
#   bash bootstrap.sh --fleet pve
# The helper is verified against EXPECTED_HELPER_SHA256 below; both files are
# reviewed together, so a tampered helper cannot pass a clean bootstrap.
#
# Usage:
#   bootstrap.sh --fleet pve|vm [--vault-addr URL] [--vault-cacert PATH]
#                [--with-cache] [--ssh-key]
#
# Flags:
#   --fleet F         which fleet token this host reads (pve|vm). Required on
#                     first run; later runs keep the existing config.
#   --vault-addr URL  override the default Vault address
#   --vault-cacert P  path to an internal CA bundle for the Vault listener
#   --with-cache      chain git's in-memory cache helper (25 min) before the
#                     vault helper; git >=2.41 honors password_expiry_utc so
#                     a cached token is never used past its GitHub expiry
#   --ssh-key         ALSO install the SSH fallback transport (edge cases
#                     only; requires the host's AppRole to carry the
#                     github-ssh-key-ro policy). HTTPS remains the standard.
#
# After this script: place /etc/git-vault/{role-id,secret-id} (root:root, 600)
# and test:  git ls-remote https://github.com/Impulse-Engineering/<repo>.git HEAD

set -euo pipefail

DEFAULT_VAULT_ADDR="https://vault.impeng.net:8200"
EXPECTED_HELPER_SHA256="87509788d7df62dbff57f9fc358a443da7549f3bcecb6b78dee7582efa82963e"
HELPER_DST=/usr/local/bin/git-credential-vault
CONF_DIR=/etc/git-vault
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

log() { printf '%s: [%s] %s\n' "$(date)" "$(whoami)" "$*"; }
err() { log "FATAL: $*"; exit 1; }

[[ $EUID -eq 0 ]] || err "must run as root"

FLEET="" VAULT_ADDR_ARG="" VAULT_CACERT_ARG="" WITH_CACHE=false SSH_KEY_MODE=false
while (( $# > 0 )); do
  case "$1" in
    --fleet)        FLEET="${2:?--fleet needs a value}"; shift 2 ;;
    --vault-addr)   VAULT_ADDR_ARG="${2:?--vault-addr needs a value}"; shift 2 ;;
    --vault-cacert) VAULT_CACERT_ARG="${2:?--vault-cacert needs a value}"; shift 2 ;;
    --with-cache)   WITH_CACHE=true; shift ;;
    --ssh-key)      SSH_KEY_MODE=true; shift ;;
    -h|--help)      { grep -E '^# (Usage:|Flags:|  )' "$0" || true; } | sed 's/^# \{0,1\}//'; exit 0 ;;
    *)              err "unknown argument: $1" ;;
  esac
done
if [[ -n "$FLEET" && "$FLEET" != "pve" && "$FLEET" != "vm" ]]; then
  err "--fleet must be pve or vm"
fi
# These values are written into files that are root-sourced and parsed by
# systemd — validate hard so no shell metacharacters or newlines ride along.
if [[ -n "$VAULT_ADDR_ARG" && ! "$VAULT_ADDR_ARG" =~ ^https?://[A-Za-z0-9.:_-]+$ ]]; then
  err "--vault-addr must be a plain http(s)://host[:port] URL"
fi
if [[ -n "$VAULT_CACERT_ARG" && ! "$VAULT_CACERT_ARG" =~ ^[A-Za-z0-9./_-]+$ ]]; then
  err "--vault-cacert must be a plain filesystem path"
fi

# ---------------------------------------------------------------------------
# Step 1 — Vault CLI (Debian/apt or RHEL-family/dnf), then mask vault.service
# ---------------------------------------------------------------------------
[[ -f /etc/os-release ]] || err "/etc/os-release missing"
# shellcheck source=/dev/null
. /etc/os-release
os_id="${ID:-unknown}" os_like="${ID_LIKE:-}"

# HashiCorp's published signing-key fingerprint — pinned and verified before
# the keyring is trusted (matches the sha256-pinning posture of the rest of
# this script).
HASHICORP_GPG_FPR="798AEC654E5C15428C8E42EEAA16FCBCA621E701"

install_debian() {
  local keyring=/usr/share/keyrings/hashicorp-archive-keyring.gpg
  local list=/etc/apt/sources.list.d/hashicorp.list
  local codename="${HASHICORP_CODENAME:-${VERSION_CODENAME:-}}"
  [[ -n "$codename" ]] || err "cannot determine Debian codename (set HASHICORP_CODENAME=)"
  if [[ ! -f "$keyring" ]]; then
    command -v gpg >/dev/null || apt-get install -y gnupg >/dev/null
    local tmpkr; tmpkr="$(mktemp)"
    curl -fsSL https://apt.releases.hashicorp.com/gpg | gpg --dearmor -o "$tmpkr" \
      || { rm -f "$tmpkr"; err "failed to fetch/dearmor HashiCorp signing key"; }
    local fpr
    fpr="$(gpg --show-keys --with-colons "$tmpkr" | awk -F: '$1=="fpr"{print $10; exit}')"
    [[ "$fpr" == "$HASHICORP_GPG_FPR" ]] \
      || { rm -f "$tmpkr"; err "HashiCorp key fingerprint mismatch (got ${fpr:-none}) — refusing"; }
    install -m 0644 "$tmpkr" "$keyring" && rm -f "$tmpkr"
  fi
  local desired="deb [signed-by=$keyring] https://apt.releases.hashicorp.com $codename main"
  if [[ ! -f "$list" ]] || [[ "$(cat "$list")" != "$desired" ]]; then
    printf '%s\n' "$desired" > "$list"
  fi
  if ! apt-get update -o Dir::Etc::sourcelist="$list" -o Dir::Etc::sourceparts=/dev/null 2>&1 | tail -1; then
    err "apt update failed for HashiCorp repo — codename '$codename' may not be published yet; re-run with HASHICORP_CODENAME=bookworm"
  fi
  command -v vault >/dev/null || apt-get install -y vault
}

install_rhel() {
  # Managed repo file: byte-compared, self-healing against stale content.
  local repo_file=/etc/yum.repos.d/hashicorp.repo desired
  read -r -d '' desired <<'REPO' || true
[hashicorp]
name=Hashicorp Stable - $basearch
baseurl=https://rpm.releases.hashicorp.com/RHEL/$releasever/$basearch/stable
enabled=1
gpgcheck=1
gpgkey=https://rpm.releases.hashicorp.com/gpg
REPO
  local pkgmgr
  if   command -v dnf >/dev/null; then pkgmgr=dnf
  elif command -v yum >/dev/null; then pkgmgr=yum
  else err "neither dnf nor yum found"; fi
  if [[ ! -f "$repo_file" ]] || ! diff -q <(printf '%s\n' "$desired") "$repo_file" >/dev/null 2>&1; then
    printf '%s\n' "$desired" > "${repo_file}.tmp" && chmod 0644 "${repo_file}.tmp" && mv -f "${repo_file}.tmp" "$repo_file"
    "$pkgmgr" -q makecache >/dev/null 2>&1 || true
  fi
  command -v vault >/dev/null || "$pkgmgr" install -y vault
}

case "$os_id:$os_like" in
  debian:*|*:*debian*) install_debian ;;
  rhel:*|ol:*|centos:*|rocky:*|almalinux:*|*:*rhel*|*:*fedora*) install_rhel ;;
  *) err "unsupported OS '$os_id' (ID_LIKE='$os_like')" ;;
esac

# Mask vault.service — a client host must never run a Vault server. HARD error
# on failure (security invariant), asserted on every run. Skipped only where
# systemd is not PID 1 (containers) — no systemd, no unit to run.
if [[ -d /run/systemd/system ]]; then
  if [[ "$(systemctl is-enabled vault 2>/dev/null || true)" != "masked" ]]; then
    systemctl stop vault 2>/dev/null || true
    systemctl disable vault 2>/dev/null || true
    systemctl mask vault || err "failed to mask vault.service"
  fi
  [[ "$(systemctl is-enabled vault 2>/dev/null || true)" == "masked" ]] || err "vault.service not masked"
else
  log "WARN: no systemd — skipping vault.service mask (nothing to run it anyway)"
fi

# ---------------------------------------------------------------------------
# Step 2 — /etc/git-vault/config (KEY=value; shell-sourceable AND valid as a
# systemd EnvironmentFile — the renewer's units read this same file)
# ---------------------------------------------------------------------------
install -d -m 0755 "$CONF_DIR"
if [[ ! -f "$CONF_DIR/config" ]]; then
  [[ -n "$FLEET" ]] || err "--fleet pve|vm required on first run (no existing $CONF_DIR/config)"
  {
    printf 'VAULT_ADDR=%s\n' "${VAULT_ADDR_ARG:-$DEFAULT_VAULT_ADDR}"
    [[ -n "$VAULT_CACERT_ARG" ]] && printf 'VAULT_CACERT=%s\n' "$VAULT_CACERT_ARG"
    printf 'GIT_VAULT_TOKEN_PATH=secret/github/fleet/%s/token\n' "$FLEET"
  } > "$CONF_DIR/config"
  chmod 0640 "$CONF_DIR/config"
  log "wrote $CONF_DIR/config (fleet=$FLEET)"
else
  log "$CONF_DIR/config exists — keeping it (edit manually to change fleet/addr)"
fi

# Interactive convenience only — cron/systemd consumers get VAULT_ADDR from
# $CONF_DIR/config, never from profile.d. Value is re-validated and emitted
# single-quoted: profile.d runs in EVERY user's login shell.
profile_addr="$(sed -n 's/^VAULT_ADDR=//p' "$CONF_DIR/config" | head -1)"
if [[ "$profile_addr" =~ ^https?://[A-Za-z0-9.:_-]+$ ]]; then
  printf "export VAULT_ADDR='%s'\n" "$profile_addr" > /etc/profile.d/vault.sh
else
  log "WARN: VAULT_ADDR in config failed validation — not writing profile.d/vault.sh"
fi

# ---------------------------------------------------------------------------
# Step 3 — credential helper (sha256-verified), scoped to github.com only
# ---------------------------------------------------------------------------
[[ -f "$HERE/git-credential-vault" ]] \
  || err "git-credential-vault not found next to this script — fetch both files from the same pinned commit (see header)"
if   command -v sha256sum >/dev/null; then SHA_TOOL="sha256sum"
elif command -v shasum   >/dev/null; then SHA_TOOL="shasum -a 256"
else err "need sha256sum or shasum"; fi
# Copy to a root-only path FIRST, hash THAT, install THAT — hashing the copy
# in a possibly world-writable download dir (/tmp) would be a TOCTOU window.
helper_tmp="$(mktemp /root/.git-credential-vault.XXXXXX)"
cp "$HERE/git-credential-vault" "$helper_tmp"
actual_sha="$($SHA_TOOL "$helper_tmp" | awk '{print $1}')"
[[ "$actual_sha" == "$EXPECTED_HELPER_SHA256" ]] \
  || { rm -f "$helper_tmp"; err "git-credential-vault sha256 mismatch (got $actual_sha) — refusing to install an unreviewed helper"; }
install -m 0755 "$helper_tmp" "$HELPER_DST"
rm -f "$helper_tmp"

# Host-scoped helper for https://github.com. The empty-string reset clears
# earlier entries at system AND global scope, so no stray `store`/custom
# helper at those levels can see or persist the token. LIMIT: a repo-local
# .git/config helper is still parsed after these; git's default
# safe.directory refusal (root won't operate in repos owned by others) is
# the guard there — do not add safe.directory='*' on these hosts.
helpers=("$HELPER_DST")
$WITH_CACHE && helpers=("cache --timeout=1500" "$HELPER_DST")
for scope in --system --global; do
  # --replace-all collapses every prior entry at this scope into the single
  # "" reset, then our helpers are appended — idempotent across re-runs.
  git config "$scope" --replace-all credential.https://github.com.helper ""
  for h in "${helpers[@]}"; do
    git config "$scope" --add credential.https://github.com.helper "$h"
  done
done

log "helper installed + scoped (system+global): $(git config --system --get-all credential.https://github.com.helper | tr '\n' ' ')"

# ---------------------------------------------------------------------------
# Step 4 (optional) — SSH fallback transport
# ---------------------------------------------------------------------------
if $SSH_KEY_MODE; then
  [[ -f "$CONF_DIR/role-id" && -f "$CONF_DIR/secret-id" ]] \
    || err "--ssh-key needs $CONF_DIR/{role-id,secret-id} in place (AppRole must carry github-ssh-key-ro)"
  # shellcheck source=/dev/null
  source "$CONF_DIR/config"
  export VAULT_ADDR ${VAULT_CACERT:+VAULT_CACERT}
  VAULT_TOKEN="$(vault write -field=token auth/approle/login \
      role_id=@"$CONF_DIR/role-id" secret_id=@"$CONF_DIR/secret-id")" \
    || err "AppRole login failed"
  export VAULT_TOKEN
  trap 'vault token revoke -self >/dev/null 2>&1 || true' EXIT

  install -d -m 0700 /root/.ssh
  # create-then-fill at 0600 so the key is never readable at umask default
  install -m 0600 /dev/null /root/.ssh/impulse-github.tmp
  vault kv get -field=private_key secret/github/org/ssh-deploy-key > /root/.ssh/impulse-github.tmp \
    || { rm -f /root/.ssh/impulse-github.tmp; err "cannot read ssh-deploy-key (policy github-ssh-key-ro attached?)"; }
  mv -f /root/.ssh/impulse-github.tmp /root/.ssh/impulse-github

  # ssh_config is FIRST-match-wins: remove prior managed stanzas and any
  # stanza whose pattern list is EXACTLY github.com (indented Host lines
  # included), then PREPEND the managed one. A stanza like
  # "Host github.com foo" is left alone (removing it would break 'foo') —
  # ours still wins for github.com by coming first — but we warn.
  touch /root/.ssh/config && chmod 0600 /root/.ssh/config
  if grep -E '^[ \t]*Host[ \t]' /root/.ssh/config | grep -F 'github.com' \
       | grep -Evq '^[ \t]*Host[ \t]+github\.com[ \t]*$'; then
    log "WARN: an existing multi-pattern 'Host ... github.com ...' stanza was kept (managed stanza takes precedence for github.com)"
  fi
  awk 'BEGIN{skip=0}
       /^[ \t]*Host[ \t]/{skip = ($0 ~ /^[ \t]*Host[ \t]+github\.com[ \t]*$/) ? 1 : 0}
       /^# managed by keyvault bootstrap --ssh-key/{next}
       skip==0{print}' /root/.ssh/config > /root/.ssh/config.new
  {
    printf '# managed by keyvault bootstrap --ssh-key (do not edit this stanza)\n'
    printf 'Host github.com\n  User git\n  IdentityFile /root/.ssh/impulse-github\n  IdentitiesOnly yes\n\n'
    cat /root/.ssh/config.new
  } > /root/.ssh/config.new2
  mv -f /root/.ssh/config.new2 /root/.ssh/config
  rm -f /root/.ssh/config.new
  chmod 0600 /root/.ssh/config

  # Statically pinned GitHub host keys (published at
  # https://api.github.com/meta; reviewed into this script — NOT keyscanned at
  # runtime, and NOT StrictHostKeyChecking=no). ENFORCED, not add-only: every
  # existing unhashed github.com entry (incl. @revoked/@cert-authority
  # markers and stale/hostile keys) is removed, then exactly these three are
  # written. If GitHub rotates keys, this script gets a reviewed update and
  # hosts re-run it.
  touch /root/.ssh/known_hosts
  awk '$1 == "github.com" {next}
       $1 ~ /^@/ && $2 == "github.com" {next}
       {print}' /root/.ssh/known_hosts > /root/.ssh/known_hosts.new
  cat >> /root/.ssh/known_hosts.new <<'HOSTKEYS'
github.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl
github.com ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBEmKSENjQEezOmxkZMy7opKgwFB9nkt5YRrYMjNuG5N87uRgg6CLrbo5wAdT/y6v0mKV0U2w0WZ2YB/++Tpockg=
github.com ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCj7ndNxQowgcQnjshcLrqPEiiphnt+VTTvDP6mHBL9j1aNUkY4Ue1gvwnGLVlOhGeYrnZaMgRK6+PKCUXaDbC7qtbW8gIkhL7aGCsOr/C56SJMy/BCZfxd1nWzAOxSDPgVsmerOBYfNqltV9/hWCqBywINIR+5dIg6JTJ72pcEpEjcYgXkE2YEFXV1JHnsKgbLWNlhScqb2UmyRkQyytRLtL+38TGxkxCflmO+5Z8CSSNY7GidjMIZ7Q4zMjA2n1nGrlTDkzwDCsw+wqFPGQA179cnfGWOWRVruj16z6XyvxvjJwbz0wQZ75XK5tKSb7FNyeIEs4TT4jk+S4dhPeAUC5y+bDYirYgM4GC7uEnztnZyaVWQ7B381AK4Qdrwt51ZqExKbQpTUNn+EjqoTwvqNj4kqx5QUCI0ThS/YkOxJCXmPUWZbhjpCg56i+2aB6CmK2JGhn57K5mj0MNdBXA4/WnwH6XoPWJzK5Nyu2zB3nAZp+S5hpQs+p1vN1/wsjk=
HOSTKEYS
  mv -f /root/.ssh/known_hosts.new /root/.ssh/known_hosts
  chmod 0600 /root/.ssh/known_hosts
  log "SSH fallback installed (key + prepended stanza + pinned host keys)"
fi

# ---------------------------------------------------------------------------
# Preflight report (warn, don't fail — creds may arrive after this script)
# ---------------------------------------------------------------------------
missing=""
[[ -f "$CONF_DIR/role-id"   ]] || missing+=" role-id"
[[ -f "$CONF_DIR/secret-id" ]] || missing+=" secret-id"
[[ -n "$missing" ]] && log "WARN: missing$missing in $CONF_DIR — place them (root:root, 600) before git will work"

# shellcheck source=/dev/null
source "$CONF_DIR/config"
export VAULT_ADDR ${VAULT_CACERT:+VAULT_CACERT}
if vault status >/dev/null 2>&1; then
  log "Vault reachable at $VAULT_ADDR"
else
  log "WARN: Vault not reachable at $VAULT_ADDR (network/TLS?) — git will fail until it is"
fi
log "bootstrap complete. Test: git ls-remote https://github.com/Impulse-Engineering/<repo>.git HEAD"
