#!/bin/zsh
# Local chooser launcher. No downloads, uploads, target execution or chmod.
set -eu
tool="${0:A:h}/executable-inspector.mjs"
if [[ ! -f "$tool" ]]; then
  tool=$(/usr/bin/osascript -e 'POSIX path of (choose file with prompt "Select the downloaded executable-inspector.mjs tool. Its location is not assumed.")') || exit 0
fi
if [[ ! -f "$tool" || ! -r "$tool" || "${tool:e}" != mjs ]]; then
  print -u2 'TOOL_NOT_FOUND: Select the downloaded, readable .mjs inspector tool.'
  exit 1
fi
node_path=$(command -v node || true)
if [[ -z "$node_path" ]]; then
  node_path=$(/usr/bin/osascript -e 'POSIX path of (choose file with prompt "Select your installed Node.js executable (version 20+). Cancel if Node.js is not installed.")') || exit 0
fi
if [[ ! -f "$node_path" || ! -x "$node_path" ]]; then
  print -u2 'NODE_NOT_FOUND: Install Node.js 20+ from its official source, or select its executable.'
  exit 1
fi
version=$("$node_path" --version) || exit 1
major=${version#v}
major=${major%%.*}
case "$version" in v[0-9]*.*) ;; *) print -u2 'NODE_VERSION_UNSUPPORTED'; exit 1;; esac
case "$major" in ''|*[!0-9]*) print -u2 'NODE_VERSION_UNSUPPORTED'; exit 1;; esac
if (( major < 20 )); then
  print -u2 'NODE_VERSION_UNSUPPORTED: Node.js 20+ is required.'
  exit 1
fi
tool_version=$("$node_path" "$tool" --version 2>/dev/null || true)
if [[ "$tool_version" != 'VELTHARA executable inspector 2026-10-29.4' ]]; then
  tool=$(/usr/bin/osascript -e 'POSIX path of (choose file with prompt "The inspector is missing or outdated. Select the newly downloaded executable-inspector.mjs.")') || exit 0
  if [[ ! -f "$tool" || ! -r "$tool" ]]; then print -u2 'TOOL_NOT_FOUND'; exit 1; fi
  tool_version=$("$node_path" "$tool" --version 2>/dev/null || true)
  if [[ "$tool_version" != 'VELTHARA executable inspector 2026-10-29.4' ]]; then
    print -u2 'TOOL_OUTDATED: Download the inspector and Mac launcher together from the site.'
    exit 1
  fi
fi
exec "$node_path" "$tool" --choose
