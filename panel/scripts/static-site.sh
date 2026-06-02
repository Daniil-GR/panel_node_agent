#!/usr/bin/env bash
set -euo pipefail

PANEL_CONFIG="${PANEL_CONFIG:-/etc/rixxx-panel/config.json}"

log_info() { echo "[INFO] $*"; }
log_warn() { echo "[WARN] $*"; }
die() { echo "[ERROR] $*" >&2; exit 1; }

command -v python3 >/dev/null 2>&1 || die "python3 is required"

cfg() {
  local key="$1"
  python3 - "$PANEL_CONFIG" "$key" <<'PY'
import json, sys
path, key = sys.argv[1], sys.argv[2]
try:
    data = json.load(open(path))
except Exception:
    data = {}
cur = data
for part in key.split('.'):
    if not isinstance(cur, dict):
        cur = ""
        break
    cur = cur.get(part, "")
if isinstance(cur, bool):
    print("true" if cur else "false")
elif cur is None:
    print("")
else:
    print(cur)
PY
}

domain() { cfg domain; }

site_enabled() {
  local enabled; enabled="$(cfg staticSite.enabled)"
  [[ "$enabled" == "true" ]]
}

site_root() {
  local root domain_name
  root="$(cfg staticSite.root)"
  domain_name="$(domain)"
  if [[ -n "$root" ]]; then
    echo "$root"
  else
    echo "/var/www/${domain_name}/dist"
  fi
}

site_base() {
  dirname "$(site_root)"
}

state_file() {
  echo "$(site_base)/.vetka-static-site.json"
}

current_release() {
  local root
  root="$(site_root)"
  if [[ -L "$root" ]]; then
    readlink -f "$root" 2>/dev/null || true
  else
    echo ""
  fi
}

point_root_to_release() {
  local release_dir="$1"
  local root
  root="$(site_root)"
  if [[ -e "$root" && ! -L "$root" ]]; then
    if [[ -d "$root" ]] && ! find "$root" -mindepth 1 -maxdepth 1 -print -quit | grep -q .; then
      rmdir "$root"
    else
      die "Static site root exists and is not an empty directory or symlink: $root"
    fi
  fi
  ln -sfnT "$release_dir" "$root"
}

write_state() {
  local release_dir="$1"
  python3 - "$PANEL_CONFIG" "$(state_file)" "$release_dir" <<'PY'
import json, os, sys
config_path, state_path, release_dir = sys.argv[1], sys.argv[2], sys.argv[3]
data = json.load(open(config_path))
site = data.get("staticSite") or {}
domain = data.get("domain", "")
root = site.get("root") or f"/var/www/{domain}/dist"
state = {
    "enabled": bool(site.get("enabled", False)),
    "domain": domain,
    "root": root,
    "sourceType": site.get("sourceType", ""),
    "sourceUrl": site.get("sourceUrl", ""),
    "installedAt": __import__("datetime").datetime.utcnow().replace(microsecond=0).isoformat() + "Z",
    "releaseDir": release_dir,
    "managedBy": "panel_node_agent",
}
os.makedirs(os.path.dirname(state_path), exist_ok=True)
with open(state_path, "w") as f:
    json.dump(state, f, indent=2)
PY
}

cmd_status() {
  local root release source enabled state
  root="$(site_root)"
  release="$(current_release)"
  source="$(cfg staticSite.sourceUrl)"
  enabled="$(cfg staticSite.enabled)"
  state="$(state_file)"
  echo "enabled: ${enabled:-false}"
  echo "root: $root"
  echo "sourceUrl: ${source:-}"
  echo "installed: $([[ -f "$root/index.html" ]] && echo yes || echo no)"
  echo "currentRelease: ${release:-}"
  echo "stateFile: $state"
}

normalize_release() {
  local release_dir="$1"
  if [[ -f "$release_dir/index.html" ]]; then
    return 0
  fi
  local child_count child
  child_count="$(find "$release_dir" -mindepth 1 -maxdepth 1 -type d | wc -l | tr -d ' ')"
  if [[ "$child_count" == "1" ]]; then
    child="$(find "$release_dir" -mindepth 1 -maxdepth 1 -type d | head -1)"
    if [[ -f "$child/index.html" ]]; then
      find "$child" -mindepth 1 -maxdepth 1 -exec mv {} "$release_dir/" \;
      rmdir "$child"
    fi
  fi
  [[ -f "$release_dir/index.html" ]] || die "Archive does not contain index.html"
}

cmd_deploy() {
  site_enabled || die "staticSite.enabled is false"
  local source_type source_url root base releases release_dir tmp archive
  source_type="$(cfg staticSite.sourceType)"
  source_url="$(cfg staticSite.sourceUrl)"
  [[ "$source_type" == "archive_url" ]] || die "Unsupported sourceType: ${source_type:-}"
  [[ -n "$source_url" ]] || die "staticSite.sourceUrl is empty"

  root="$(site_root)"
  base="$(site_base)"
  releases="$base/releases"
  release_dir="$releases/$(date -u +%Y%m%d%H%M%S)"
  tmp="$(mktemp -d)"
  archive="$tmp/dist.tar.gz"
  trap 'rm -rf "$tmp"' RETURN

  mkdir -p "$release_dir"
  log_info "Downloading static site archive: $source_url"
  curl -fsSL "$source_url" -o "$archive"
  tar -tzf "$archive" >/dev/null
  tar -xzf "$archive" -C "$release_dir"
  normalize_release "$release_dir"

  point_root_to_release "$release_dir"
  if ! id caddy >/dev/null 2>&1 && [[ "${EUID:-$(id -u)}" -eq 0 ]]; then
    useradd --system --no-create-home --shell /usr/sbin/nologin caddy
  fi
  id caddy >/dev/null 2>&1 && chown -R caddy:caddy "$base"
  find "$base" -type d -exec chmod 755 {} +
  find "$base" -type f -exec chmod 644 {} +
  write_state "$release_dir"
  log_info "Static site deployed to $root"
}

cmd_rollback() {
  local root base current previous
  root="$(site_root)"
  base="$(site_base)"
  current="$(current_release)"
  previous="$(find "$base/releases" -mindepth 1 -maxdepth 1 -type d 2>/dev/null | sort | grep -v "^${current}$" | tail -1 || true)"
  [[ -n "$previous" ]] || die "No previous release found"
  [[ -f "$previous/index.html" ]] || die "Previous release has no index.html"
  point_root_to_release "$previous"
  write_state "$previous"
  log_info "Rolled back static site to $previous"
}

case "${1:-status}" in
  status) cmd_status ;;
  deploy) cmd_deploy ;;
  rollback) cmd_rollback ;;
  *) die "Usage: $0 {status|deploy|rollback}" ;;
esac
