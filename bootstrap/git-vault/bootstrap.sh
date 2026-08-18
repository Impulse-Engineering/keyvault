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
#   2. Writes /etc/git-vault/config (VAULT_ADDR, auth method, fleet token path).
#   3. Installs the git-credential-vault helper (sha256-verified against the
#      hash reviewed into THIS script) and scopes it to github.com only.
#   4. --auth-method agent: installs a root Vault Agent cert-auth profile and
#      token sink; initial client certificate enrollment is out-of-band.
#   5. --ssh-key: optional SSH fallback transport (see below).
#
# Supply chain: ALWAYS fetch this script and the helper pinned to a commit
# SHA, never a branch:
#   C=<reviewed commit sha>
#   curl -fsSLO https://raw.githubusercontent.com/Impulse-Engineering/keyvault/$C/bootstrap/git-vault/bootstrap.sh
#   curl -fsSLO https://raw.githubusercontent.com/Impulse-Engineering/keyvault/$C/bootstrap/git-vault/git-credential-vault
#   curl -fsSLO https://raw.githubusercontent.com/Impulse-Engineering/keyvault/$C/bootstrap/git-vault/git-vault-install-client-cert
#   bash bootstrap.sh --fleet pve
# The helper and Agent installer are verified against their expected SHA-256
# values below; all three files are reviewed together, so a tampered consumer
# cannot pass a clean bootstrap.
#
# Usage:
#   bootstrap.sh --fleet pve|vm [--auth-method approle|agent]
#                [--cert-role git-cert-vm|git-cert-pve|git-cert-archive]
#                [--cert-hostname HOST] [--cert-domain DOMAIN]
#                [--client-cert PATH] [--client-key PATH]
#                [--agent-token PATH] [--vault-addr URL] [--vault-cacert PATH]
#                [--with-cache] [--ssh-key]
#
# Flags:
#   --fleet F         which access profile this host uses. Required on first
#                     run; later runs keep the existing config.
#                       pve — reads a token scoped to the Proxmox repo only
#                             (hypervisors have a small, stable repo need)
#                       vm  — reads an installation-wide read-only token, so
#                             any repo the GitHub App is installed on works
#                             without per-repo Vault config
#   --vault-addr URL  override the default Vault address
#   --vault-cacert P  path to an internal CA bundle for the Vault listener
#   --auth-method M   approle (default; existing behavior) or agent. Agent
#                     authenticates Vault Agent with the host client cert.
#   --cert-role R     cert-auth role for the Agent profile. Defaults to
#                     git-cert-pve for --fleet pve or git-cert-vm for --fleet vm.
#                     Use git-cert-archive for an archive writer.
#   --cert-hostname H hostname used in the client certificate CN/DNS SAN;
#                     defaults to hostname -s.
#   --cert-domain D   DNS suffix used in the client certificate CN/DNS SAN;
#                     defaults to the existing config value, or the suffix
#                     reported by hostname -f. Required if neither is usable.
#   --client-cert P  initial client certificate (default /etc/git-vault/client.crt)
#   --client-key P   initial client key (default /etc/git-vault/client.key)
#   --agent-token P  Agent token sink (default /run/vault-agent/token)
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
EXPECTED_HELPER_SHA256="662318a98133603b72c50f61fe39c638918e8f8e864ab7754b1132a2dcacd705"
EXPECTED_INSTALLER_SHA256="7a0b822be9b8b9fbe5a4cbc4823470262802a7b493ced3f0e980f40d92975483"
HELPER_DST=/usr/local/bin/git-credential-vault
INSTALLER_DST=/usr/local/sbin/git-vault-install-client-cert
CONF_DIR=/etc/git-vault
AGENT_DIR=/etc/vault-agent
AGENT_CONFIG="$AGENT_DIR/config.hcl"
AGENT_TEMPLATE="$AGENT_DIR/git-client.ctmpl"
AGENT_UNIT=/etc/systemd/system/vault-agent-git.service
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

log() { printf '%s: [%s] %s\n' "$(date)" "$(whoami)" "$*"; }
err() { log "FATAL: $*"; exit 1; }

root_only_file() {
  local f="$1" perms owner mode group_bits other_bits
  [[ -f "$f" ]] || err "$f missing"
  perms=$(stat -c '%u %a' "$f" 2>/dev/null || stat -f '%u %Lp' "$f")
  read -r owner mode <<< "$perms"
  [[ "$owner" == 0 ]] || err "$f must be owned by root (owner=$owner)"
  group_bits="${mode: -2:1}" ; other_bits="${mode: -1}"
  [[ "$group_bits" == 0 && "$other_bits" == 0 ]] \
    || err "$f must be root-only (mode 600 or stricter; got $mode)"
}

[[ $EUID -eq 0 ]] || err "must run as root"

FLEET="" VAULT_ADDR_ARG="" VAULT_CACERT_ARG="" AUTH_METHOD_ARG=""
CERT_ROLE_ARG="" CERT_HOSTNAME_ARG="" CERT_DOMAIN_ARG=""
CLIENT_CERT_ARG=/etc/git-vault/client.crt
CLIENT_KEY_ARG=/etc/git-vault/client.key AGENT_TOKEN_ARG=/run/vault-agent/token
CLIENT_CERT_SET=false CLIENT_KEY_SET=false AGENT_TOKEN_SET=false
CERT_HOSTNAME_SET=false CERT_DOMAIN_SET=false
WITH_CACHE=false SSH_KEY_MODE=false
while (( $# > 0 )); do
  case "$1" in
    --fleet)        FLEET="${2:?--fleet needs a value}"; shift 2 ;;
    --auth-method)  AUTH_METHOD_ARG="${2:?--auth-method needs a value}"; shift 2 ;;
    --cert-role)    CERT_ROLE_ARG="${2:?--cert-role needs a value}"; shift 2 ;;
    --cert-hostname) CERT_HOSTNAME_ARG="${2:?--cert-hostname needs a value}"; CERT_HOSTNAME_SET=true; shift 2 ;;
    --cert-domain) CERT_DOMAIN_ARG="${2:?--cert-domain needs a value}"; CERT_DOMAIN_SET=true; shift 2 ;;
    --client-cert)  CLIENT_CERT_ARG="${2:?--client-cert needs a value}"; CLIENT_CERT_SET=true; shift 2 ;;
    --client-key)   CLIENT_KEY_ARG="${2:?--client-key needs a value}"; CLIENT_KEY_SET=true; shift 2 ;;
    --agent-token)  AGENT_TOKEN_ARG="${2:?--agent-token needs a value}"; AGENT_TOKEN_SET=true; shift 2 ;;
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
if [[ -n "$AUTH_METHOD_ARG" && "$AUTH_METHOD_ARG" != "approle" && "$AUTH_METHOD_ARG" != "agent" ]]; then
  err "--auth-method must be approle or agent"
fi
if [[ -n "$CERT_ROLE_ARG" && "$CERT_ROLE_ARG" != "git-cert-vm" && "$CERT_ROLE_ARG" != "git-cert-pve" && "$CERT_ROLE_ARG" != "git-cert-archive" ]]; then
  err "--cert-role must be git-cert-vm, git-cert-pve, or git-cert-archive"
fi
# These values are written into files that are root-sourced and parsed by
# systemd — validate hard so no shell metacharacters or newlines ride along.
if [[ -n "$VAULT_ADDR_ARG" && ! "$VAULT_ADDR_ARG" =~ ^https?://[A-Za-z0-9.:_-]+$ ]]; then
  err "--vault-addr must be a plain http(s)://host[:port] URL"
fi
if [[ -n "$VAULT_CACERT_ARG" && ! "$VAULT_CACERT_ARG" =~ ^[A-Za-z0-9./_-]+$ ]]; then
  err "--vault-cacert must be a plain filesystem path"
fi
for path_arg in "$CLIENT_CERT_ARG" "$CLIENT_KEY_ARG" "$AGENT_TOKEN_ARG"; do
  [[ "$path_arg" = /* && "$path_arg" =~ ^[A-Za-z0-9./_-]+$ ]] \
    || err "client/Agent paths must be absolute plain filesystem paths"
done
if [[ -n "$CERT_HOSTNAME_ARG" && ! "$CERT_HOSTNAME_ARG" =~ ^[A-Za-z0-9][A-Za-z0-9-]*$ ]]; then
  err "--cert-hostname must be a DNS hostname label (letters, numbers, hyphens)"
fi
if [[ -n "$CERT_DOMAIN_ARG" && ! "$CERT_DOMAIN_ARG" =~ ^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)+$ ]]; then
  err "--cert-domain must be a DNS domain such as aseva.net"
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
fleet_token_path() {
  case "$1" in
    pve) printf '%s\n' 'secret/github/fleet/pve/token' ;;
    vm)  printf '%s\n' 'secret/github/read/all' ;;
    *)   err "internal error: unknown fleet '$1'" ;;
  esac
}

fleet_cert_role() {
  case "$1" in
    pve) printf '%s\n' 'git-cert-pve' ;;
    vm)  printf '%s\n' 'git-cert-vm' ;;
    *)   err "internal error: unknown fleet '$1'" ;;
  esac
}

CONFIG_EXISTS=false
EXISTING_AUTH_METHOD=""
EXISTING_ADDR=""
EXISTING_CACERT=""
EXISTING_TOKEN_PATH=""
EXISTING_CERT_ROLE=""
EXISTING_CERT_HOSTNAME=""
EXISTING_CERT_DOMAIN=""
EXISTING_CLIENT_CERT=""
EXISTING_CLIENT_KEY=""
EXISTING_AGENT_TOKEN=""
if [[ -f "$CONF_DIR/config" ]]; then
  CONFIG_EXISTS=true
  EXISTING_AUTH_METHOD="$(sed -n 's/^GIT_VAULT_AUTH_METHOD=//p' "$CONF_DIR/config" | head -1)"
  EXISTING_AUTH_METHOD="${EXISTING_AUTH_METHOD:-approle}"
  EXISTING_ADDR="$(sed -n 's/^VAULT_ADDR=//p' "$CONF_DIR/config" | head -1)"
  EXISTING_CACERT="$(sed -n 's/^VAULT_CACERT=//p' "$CONF_DIR/config" | head -1)"
  EXISTING_TOKEN_PATH="$(sed -n 's/^GIT_VAULT_TOKEN_PATH=//p' "$CONF_DIR/config" | head -1)"
  EXISTING_CERT_ROLE="$(sed -n 's/^GIT_VAULT_CERT_ROLE=//p' "$CONF_DIR/config" | head -1)"
  EXISTING_CERT_HOSTNAME="$(sed -n 's/^GIT_VAULT_CERT_HOSTNAME=//p' "$CONF_DIR/config" | head -1)"
  EXISTING_CERT_DOMAIN="$(sed -n 's/^GIT_VAULT_CERT_DOMAIN=//p' "$CONF_DIR/config" | head -1)"
  EXISTING_CLIENT_CERT="$(sed -n 's/^GIT_VAULT_CLIENT_CERT=//p' "$CONF_DIR/config" | head -1)"
  EXISTING_CLIENT_KEY="$(sed -n 's/^GIT_VAULT_CLIENT_KEY=//p' "$CONF_DIR/config" | head -1)"
  EXISTING_AGENT_TOKEN="$(sed -n 's/^GIT_VAULT_AGENT_TOKEN=//p' "$CONF_DIR/config" | head -1)"
fi

if [[ -n "$AUTH_METHOD_ARG" ]]; then
  AUTH_METHOD="$AUTH_METHOD_ARG"
else
  AUTH_METHOD="$EXISTING_AUTH_METHOD"
fi
[[ "$AUTH_METHOD" == approle || "$AUTH_METHOD" == agent ]] \
  || err "unsupported auth method in $CONF_DIR/config: $AUTH_METHOD"
if [[ "$AUTH_METHOD" != agent && ( -n "$CERT_ROLE_ARG" || -n "$CERT_HOSTNAME_ARG" || -n "$CERT_DOMAIN_ARG" || $CLIENT_CERT_SET == true || $CLIENT_KEY_SET == true || $AGENT_TOKEN_SET == true ) ]]; then
  err "certificate/Agent options require --auth-method agent"
fi
if $SSH_KEY_MODE && [[ "$AUTH_METHOD" != approle ]]; then
  err "--ssh-key currently requires --auth-method approle"
fi

if ! $CONFIG_EXISTS; then
  [[ -n "$FLEET" ]] || err "--fleet pve|vm required on first run (no existing $CONF_DIR/config)"
  token_path="$(fleet_token_path "$FLEET")"
  config_addr="${VAULT_ADDR_ARG:-$DEFAULT_VAULT_ADDR}"
  config_cacert="$VAULT_CACERT_ARG"
else
  [[ -n "$EXISTING_TOKEN_PATH" ]] || err "$CONF_DIR/config has no GIT_VAULT_TOKEN_PATH"
  # Existing behavior is intentionally keep-on-rerun. Switching auth method is
  # explicit; --fleet then updates the token path for the explicit switch.
  if [[ -n "$AUTH_METHOD_ARG" && -n "$FLEET" ]]; then
    token_path="$(fleet_token_path "$FLEET")"
  else
    token_path="$EXISTING_TOKEN_PATH"
  fi
  config_addr="$EXISTING_ADDR"
  [[ -n "$config_addr" ]] || err "$CONF_DIR/config has no VAULT_ADDR"
  config_cacert="$EXISTING_CACERT"
fi
if [[ -n "$config_cacert" && ! "$config_cacert" =~ ^[A-Za-z0-9./_-]+$ ]]; then
  err "VAULT_CACERT in $CONF_DIR/config must be a plain filesystem path"
fi

if [[ "$AUTH_METHOD" == agent ]]; then
  if [[ -n "$CERT_ROLE_ARG" ]]; then
    cert_role="$CERT_ROLE_ARG"
  elif [[ -n "$EXISTING_CERT_ROLE" ]]; then
    cert_role="$EXISTING_CERT_ROLE"
  elif [[ -n "$FLEET" ]]; then
    cert_role="$(fleet_cert_role "$FLEET")"
  fi
  case "$token_path" in
    secret/github/fleet/pve/token) cert_role="${cert_role:-git-cert-pve}" ;;
    secret/github/read/all)        cert_role="${cert_role:-git-cert-vm}" ;;
  esac
  [[ -n "${cert_role:-}" ]] || err "Agent profile needs --cert-role or a recognizable fleet token path"
  case "$cert_role" in
    git-cert-vm|git-cert-pve|git-cert-archive) ;;
    *) err "invalid Agent certificate role: $cert_role" ;;
  esac

  if $CLIENT_CERT_SET; then client_cert="$CLIENT_CERT_ARG"; elif [[ -n "$EXISTING_CLIENT_CERT" ]]; then client_cert="$EXISTING_CLIENT_CERT"; else client_cert="$CLIENT_CERT_ARG"; fi
  if $CLIENT_KEY_SET; then client_key="$CLIENT_KEY_ARG"; elif [[ -n "$EXISTING_CLIENT_KEY" ]]; then client_key="$EXISTING_CLIENT_KEY"; else client_key="$CLIENT_KEY_ARG"; fi
  if $AGENT_TOKEN_SET; then agent_token="$AGENT_TOKEN_ARG"; elif [[ -n "$EXISTING_AGENT_TOKEN" ]]; then agent_token="$EXISTING_AGENT_TOKEN"; else agent_token="$AGENT_TOKEN_ARG"; fi
  cert_hostname="${CERT_HOSTNAME_ARG:-${EXISTING_CERT_HOSTNAME:-}}"
  if [[ -z "$cert_hostname" ]]; then
    cert_hostname="$(hostname -s 2>/dev/null || true)"
  fi
  [[ "$cert_hostname" =~ ^[A-Za-z0-9][A-Za-z0-9-]*$ ]] \
    || err "cannot determine a valid short hostname for the client certificate; pass --cert-hostname"
  if $CERT_DOMAIN_SET; then
    cert_domain="$CERT_DOMAIN_ARG"
  elif [[ -n "$EXISTING_CERT_DOMAIN" ]]; then
    cert_domain="$EXISTING_CERT_DOMAIN"
  else
    host_fqdn="$(hostname -f 2>/dev/null || true)"
    if [[ "$host_fqdn" == "$cert_hostname".* ]]; then
      cert_domain="${host_fqdn#"${cert_hostname}".}"
    else
      cert_domain=""
    fi
  fi
  [[ "$cert_domain" =~ ^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)+$ ]] \
    || err "cannot determine a valid certificate DNS domain; pass --cert-domain (for example aseva.net)"
  [[ "$client_cert" = /* && "$client_cert" =~ ^[A-Za-z0-9./_-]+$ ]] \
    || err "client certificate path is invalid: $client_cert"
  [[ "$client_key" = /* && "$client_key" =~ ^[A-Za-z0-9./_-]+$ ]] \
    || err "client key path is invalid: $client_key"
  [[ "$agent_token" = /* && "$agent_token" =~ ^[A-Za-z0-9./_-]+$ ]] \
    || err "Agent token path is invalid: $agent_token"
  [[ "$agent_token" == /run/vault-agent/* ]] \
    || err "Agent token path must be under /run/vault-agent"
fi

if ! $CONFIG_EXISTS || [[ -n "$AUTH_METHOD_ARG" ]] || {
  [[ "$AUTH_METHOD" == agent ]] && {
    [[ -n "$CERT_ROLE_ARG" ]] || $CERT_HOSTNAME_SET || $CERT_DOMAIN_SET || [[ -z "$EXISTING_CERT_DOMAIN" ]] || $CLIENT_CERT_SET || $CLIENT_KEY_SET || $AGENT_TOKEN_SET
  }
}; then
  config_tmp="$CONF_DIR/config.tmp.$$"
  {
    printf 'VAULT_ADDR=%s\n' "$config_addr"
    [[ -n "$config_cacert" ]] && printf 'VAULT_CACERT=%s\n' "$config_cacert"
    printf 'GIT_VAULT_AUTH_METHOD=%s\n' "$AUTH_METHOD"
    printf 'GIT_VAULT_TOKEN_PATH=%s\n' "$token_path"
    if [[ "$AUTH_METHOD" == agent ]]; then
      printf 'GIT_VAULT_AGENT_TOKEN=%s\n' "$agent_token"
      printf 'GIT_VAULT_CERT_ROLE=%s\n' "$cert_role"
      printf 'GIT_VAULT_CERT_HOSTNAME=%s\n' "$cert_hostname"
      printf 'GIT_VAULT_CERT_DOMAIN=%s\n' "$cert_domain"
      printf 'GIT_VAULT_CLIENT_CERT=%s\n' "$client_cert"
      printf 'GIT_VAULT_CLIENT_KEY=%s\n' "$client_key"
    fi
  } > "$config_tmp"
  chown root:root "$config_tmp"
  chmod 0640 "$config_tmp"
  mv -f "$config_tmp" "$CONF_DIR/config"
  log "wrote $CONF_DIR/config (auth-method=$AUTH_METHOD token-path=$token_path)"
else
  log "$CONF_DIR/config exists — keeping it (use --auth-method to switch explicitly)"
fi

# A shell-sourceable config is root code. Refuse an existing file that is not
# root-owned and non-writable by group/other before it is used below.
config_perms=$(stat -c '%u %a' "$CONF_DIR/config" 2>/dev/null || stat -f '%u %Lp' "$CONF_DIR/config")
read -r config_owner config_mode <<< "$config_perms"
[[ "$config_owner" == 0 ]] || err "$CONF_DIR/config must be owned by root"
config_group_bits="${config_mode: -2:1}" ; config_other_bits="${config_mode: -1}"
[[ "$config_group_bits" != [2367] && "$config_other_bits" != [2367] ]] \
  || err "$CONF_DIR/config is group/world-writable (mode $config_mode)"

# Interactive convenience only — cron/systemd consumers get VAULT_ADDR from
# $CONF_DIR/config, never from profile.d. Value is re-validated and emitted
# single-quoted: profile.d runs in EVERY user's login shell.
profile_addr="$(sed -n 's/^VAULT_ADDR=//p' "$CONF_DIR/config" | head -1)"
if [[ "$profile_addr" =~ ^https?://[A-Za-z0-9.:_-]+$ ]]; then
  printf "export VAULT_ADDR='%s'\n" "$profile_addr" > /etc/profile.d/vault.sh
else
  err "VAULT_ADDR in $CONF_DIR/config failed validation"
fi
config_token_path="$(sed -n 's/^GIT_VAULT_TOKEN_PATH=//p' "$CONF_DIR/config" | head -1)"
[[ "$config_token_path" =~ ^[A-Za-z0-9/_.-]+$ ]] \
  || err "GIT_VAULT_TOKEN_PATH in $CONF_DIR/config failed validation"

# ---------------------------------------------------------------------------
# Step 3 — credential helper and Agent installer (sha256-verified), scoped to
# github.com only
# ---------------------------------------------------------------------------
[[ -f "$HERE/git-credential-vault" ]] \
  || err "git-credential-vault not found next to this script — fetch all files from the same pinned commit (see header)"
[[ -f "$HERE/git-vault-install-client-cert" ]] \
  || err "git-vault-install-client-cert not found next to this script — fetch all files from the same pinned commit"
if command -v sha256sum >/dev/null; then
  sha256_file() { sha256sum "$1"; }
elif command -v shasum >/dev/null; then
  sha256_file() { shasum -a 256 "$1"; }
else
  err "need sha256sum or shasum"
fi

install_verified() {
  local src="$1" expected="$2" dst="$3" tmp actual
  # Copy to a root-only path FIRST, hash THAT, install THAT — hashing the copy
  # in a possibly world-writable download dir (/tmp) would be a TOCTOU window.
  tmp="$(mktemp "/root/.keyvault-$(basename "$dst").XXXXXX")"
  cp "$src" "$tmp"
  actual="$(sha256_file "$tmp" | awk '{print $1}')"
  [[ "$actual" == "$expected" ]] \
    || { rm -f "$tmp"; err "$(basename "$src") sha256 mismatch (got $actual) — refusing to install an unreviewed file"; }
  install -o root -g root -m 0755 "$tmp" "$dst"
  rm -f "$tmp"
}

install_verified "$HERE/git-credential-vault" "$EXPECTED_HELPER_SHA256" "$HELPER_DST"
install_verified "$HERE/git-vault-install-client-cert" "$EXPECTED_INSTALLER_SHA256" "$INSTALLER_DST"

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
# Step 4 (agent profile) — cert auth, Vault Agent, and token sink
# ---------------------------------------------------------------------------
if [[ "$AUTH_METHOD" == agent ]]; then
  [[ -d /run/systemd/system ]] || err "--auth-method agent requires systemd"
  root_only_file "$client_cert"
  root_only_file "$client_key"
  command -v openssl >/dev/null || err "openssl is required for the Agent client certificate"
  openssl x509 -in "$client_cert" -noout -checkend 60 >/dev/null 2>&1 \
    || err "client certificate is expired or expires within 60 seconds: $client_cert"
  openssl pkey -in "$client_key" -noout >/dev/null 2>&1 \
    || err "client key is not valid PEM: $client_key"

  pki_role=""
  case "$cert_role" in
    git-cert-vm)      pki_role=git-vm ;;
    git-cert-pve)     pki_role=git-pve ;;
    git-cert-archive) pki_role=git-archive ;;
  esac
  [[ -n "$pki_role" ]] || err "no PKI role mapping for $cert_role"
  VAULT_BIN="$(command -v vault)"
  cert_fqdn="git-${cert_hostname}.${cert_domain}"

  install -d -o root -g root -m 0700 "$AGENT_DIR"
  agent_config_tmp="$AGENT_CONFIG.tmp.$$"
  {
    printf 'vault {\n'
    printf '  address = "%s"\n' "$config_addr"
    [[ -n "$config_cacert" ]] && printf '  ca_cert = "%s"\n' "$config_cacert"
    printf '}\n\n'
    cat <<EOF
auto_auth {
  method "cert" {
    mount_path = "auth/cert"
    config = {
      name          = "$cert_role"
      client_cert   = "$client_cert"
      client_key    = "$client_key"
      reload        = true
      reload_period = "1m"
    }
  }

  enable_reauth_on_new_credentials = true

  sink "file" {
    config = {
      path  = "$agent_token"
      mode  = "0600"
      owner = "root"
      group = "root"
    }
  }
}

template_config {
  lease_renewal_threshold = 0.9
}

template {
  source      = "$AGENT_TEMPLATE"
  destination = "/run/vault-agent/rendered-client-cert"
  perms       = "0600"
  command     = "$INSTALLER_DST /run/vault-agent/rendered-client-cert $client_key $client_cert"
}
EOF
  } > "$agent_config_tmp"
  chown root:root "$agent_config_tmp"
  chmod 0600 "$agent_config_tmp"
  mv -f "$agent_config_tmp" "$AGENT_CONFIG"

  agent_template_tmp="$AGENT_TEMPLATE.tmp.$$"
  cat > "$agent_template_tmp" <<EOF
{{ with pkiCert "pki-git-client/issue/$pki_role" "common_name=$cert_fqdn" "alt_names=$cert_fqdn" "ttl=720h" }}
# KEY-BEGIN
{{ .Key }}
# KEY-END
# CERT-BEGIN
{{ .Cert }}
{{ .CA }}
# CERT-END
{{ end }}
EOF
  chown root:root "$agent_template_tmp"
  chmod 0600 "$agent_template_tmp"
  mv -f "$agent_template_tmp" "$AGENT_TEMPLATE"

  cat > "$AGENT_UNIT" <<EOF
[Unit]
Description=Vault Agent for GitHub credential access
Wants=network-online.target
After=network-online.target
ConditionPathExists=$client_cert
ConditionPathExists=$client_key

[Service]
Type=simple
User=root
Group=root
UMask=0077
RuntimeDirectory=vault-agent
RuntimeDirectoryMode=0700
ExecStart=$VAULT_BIN agent -config=$AGENT_CONFIG
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=multi-user.target
EOF
  chown root:root "$AGENT_UNIT"
  chmod 0644 "$AGENT_UNIT"
  systemctl daemon-reload
  systemctl enable "$AGENT_UNIT" >/dev/null
  systemctl restart vault-agent-git.service 2>/dev/null || systemctl start vault-agent-git.service

  token_ready=false
  for _ in {1..15}; do
    if [[ -s "$agent_token" ]]; then token_ready=true; break; fi
    sleep 1
  done
  $token_ready || err "Vault Agent did not produce token sink: $agent_token (check systemctl status vault-agent-git)"
  root_only_file "$agent_token"
  log "Vault Agent cert profile enabled: role=$cert_role identity=$cert_fqdn cert=$client_cert key=$client_key token=$agent_token"
elif [[ -n "$AUTH_METHOD_ARG" && "$AUTH_METHOD_ARG" == approle && -d /run/systemd/system ]]; then
  # Explicit rollback from the Agent profile. Keep the certificate files for
  # re-enrollment/recovery, but stop the Agent so only AppRole is used.
  systemctl disable --now vault-agent-git.service 2>/dev/null || true
  log "Vault Agent disabled; AppRole is now the configured auth method"
fi

# ---------------------------------------------------------------------------
# Step 5 (optional) — SSH fallback transport
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
if [[ "$AUTH_METHOD" == approle ]]; then
  missing=""
  [[ -f "$CONF_DIR/role-id"   ]] || missing+=" role-id"
  [[ -f "$CONF_DIR/secret-id" ]] || missing+=" secret-id"
  [[ -n "$missing" ]] && log "WARN: missing$missing in $CONF_DIR — place them (root:root, 600) before git will work"
else
  log "Vault Agent mode is active; token source is ${agent_token:-/run/vault-agent/token}"
fi

# shellcheck source=/dev/null
source "$CONF_DIR/config"
export VAULT_ADDR ${VAULT_CACERT:+VAULT_CACERT}
if vault status >/dev/null 2>&1; then
  log "Vault reachable at $VAULT_ADDR"
else
  log "WARN: Vault not reachable at $VAULT_ADDR (network/TLS?) — git will fail until it is"
fi
log "bootstrap complete. Test: git ls-remote https://github.com/Impulse-Engineering/<repo>.git HEAD"
