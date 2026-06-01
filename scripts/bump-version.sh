#!/usr/bin/env bash
# Bump the plugin version (patch) and keep all version locations in sync.
set -euo pipefail

# Determine the base directory (script may be called from repo root)
BASE_DIR=$(dirname "$(realpath "$0")")/..  # go one level up to plugin root

# File paths
PLUGIN_FILE="$BASE_DIR/vapt-security.php"
PACKAGE_JSON="$BASE_DIR/package.json"
VERSION_HISTORY="$BASE_DIR/VERSION_HISTORY.md"

# Extract current version from package.json (single source of truth)
CURRENT=$(jq -r '.version' "$PACKAGE_JSON")
if [[ -z "$CURRENT" ]]; then
  echo "Unable to read version from $PACKAGE_JSON"
  exit 1
fi

# Increment patch number (x.y.z -> x.y.(z+1))
IFS='.' read -r MAJ MIN PATCH <<<"$CURRENT"
NEW_VERSION="${MAJ}.${MIN}.$((PATCH+1))"

# Update the plugin header
sed -i "s/^Version: *[0-9.]\+/Version:     $NEW_VERSION/" "$PLUGIN_FILE"

# Update package.json
jq ".version = \"$NEW_VERSION\"" "$PACKAGE_JSON" > "$PACKAGE_JSON.tmp" && mv "$PACKAGE_JSON.tmp" "$PACKAGE_JSON"

# Prepend a new entry to VERSION_HISTORY.md
TODAY=$(date +%Y-%m-%d)
{ echo "## v$NEW_VERSION - $TODAY"; echo; echo "### Added"; echo "- Bumped version to $NEW_VERSION after large refactor."; echo; cat "$VERSION_HISTORY"; } > "$VERSION_HISTORY.tmp" && mv "$VERSION_HISTORY.tmp" "$VERSION_HISTORY"

echo "Version bumped: $CURRENT → $NEW_VERSION"
